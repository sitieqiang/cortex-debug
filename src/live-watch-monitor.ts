import { DebugProtocol } from '@vscode/debugprotocol';
import { Handles } from '@vscode/debugadapter';
import { MI2 } from './backend/mi2/mi2';
import { decodeReference, ExtendedVariable, GDBDebugSession, RequestQueue } from './gdb';
import { MIError, VariableObject, BitfieldInfo } from './backend/backend';
import * as crypto from 'crypto';
import { MINode } from './backend/mi_parse';
import { expandValue } from './backend/gdb_expansion';

const enableLiveWatchPagingLog = false;

export type VariableType = string | VariableObject | ExtendedVariable;
export interface NameToVarChangeInfo {
    [name: string]: any;
}
export class VariablesHandler {
    public variableHandles = new Handles<VariableType>(256);
    public variableHandlesReverse = new Map<string, number>();
    public cachedChangeList: NameToVarChangeInfo | undefined;

    constructor(
        public isBusy: () => boolean,
        public busyError: (r: DebugProtocol.Response, a: any) => void
    ) { }

    private pagingLog(session: GDBDebugSession, message: string): void {
        if (!enableLiveWatchPagingLog) {
            return;
        }
        session.handleMsg('log', `DebugLiveWatchPaging: ${message}\n`);
    }

    private describeChildren(children: VariableObject[]): string {
        if (!children.length) {
            return 'first=<none> last=<none>';
        }
        const describe = (child: VariableObject) => {
            return `${child.exp}/${child.name}/ref=${child.id ?? 0}/numchild=${child.numchild}`;
        };
        return `first=${describe(children[0])} last=${describe(children[children.length - 1])}`;
    }

    private describeFetchProfile(children: VariableObject[]): string {
        const profile = (children as any).profile;
        if (!profile) {
            return 'miProfile=<none>';
        }
        return `miProfile=total:${profile.totalMs} list:${profile.listMs} path:${profile.parentPathMs}`
            + ` bulk:${profile.bulkReadMs ?? '<none>'}`
            + ` idx:${profile.indexedAddressDerived}/${profile.indexedAddressFailed}`
            + ` idxInfo:${profile.indexedChildAddressInfoMs}`
            + ` perChild:${profile.perChildAddressSuccesses}/${profile.perChildAddressAttempts}`
            + ` parentFallback:${profile.parentFallbackSuccesses}/${profile.parentFallbackAttempts}`
            + ` noAddress:${profile.noAddress} addr:${profile.addressMs}`;
    }

    public async clearCachedVars(miDebugger: MI2) {
        miDebugger.clearLiveWatchSearchIndexes();
        if (this.cachedChangeList) {
            const poromises = [];
            for (const name of Object.keys(this.cachedChangeList)) {
                poromises.push(miDebugger.sendCommand(`var-delete ${name}`));
            }
            this.cachedChangeList = {};
            const results = await Promise.allSettled(poromises);
            results
                .filter((r) => r.status === 'rejected')
                .forEach((r) => console.error('clearCachedValues', r.reason));
        }
    }

    private getLiveWatchVarObjName(expression: string): string {
        const hasher = crypto.createHash('sha256');
        hasher.update(expression);
        return `hover_${hasher.digest('hex')}`;
    }

    private getActiveVarObjNames(args?: RefreshAllArguments): string[] | undefined {
        if (!args || (!args.expressions && !args.variableReferences)) {
            return undefined;
        }

        const names = new Set<string>();
        for (const expression of args.expressions ?? []) {
            if (typeof expression !== 'string') {
                continue;
            }
            const name = this.getLiveWatchVarObjName(expression);
            if (this.variableHandlesReverse.get(name) !== undefined) {
                names.add(name);
            }
        }
        for (const ref of args.variableReferences ?? []) {
            if (typeof ref !== 'number' || ref <= 0) {
                continue;
            }
            const variable = this.variableHandles.get(ref);
            if (variable instanceof VariableObject) {
                names.add(variable.name);
            }
        }
        return Array.from(names);
    }

    public async refreshCachedChangeList(miDebugger: MI2, args?: RefreshAllArguments): Promise<void> {
        const activeNames = this.getActiveVarObjNames(args);
        if (activeNames && activeNames.length === 0) {
            this.cachedChangeList = undefined;
            return;
        }

        const updateNames = activeNames ?? ['*'];
        this.cachedChangeList = {};
        const applyChanges = (changes: MINode): boolean => {
            const changelist = changes.result('changelist');
            for (const change of changelist || []) {
                const name = MINode.valueOf(change, 'name');
                this.cachedChangeList[name] = change;
                const inScope = MINode.valueOf(change, 'in_scope');
                const typeChanged = MINode.valueOf(change, 'type_changed');
                if ((inScope === 'false') || (typeChanged === 'true')) {
                    // If one of these conditions happened, abandon the entire cache. TODO: Optimize later
                    this.cachedChangeList = undefined;
                    return false;
                }
                const vId = this.variableHandlesReverse.get(name);
                const v = this.variableHandles.get(vId) as any;
                if (v) {
                    v.applyChanges(change);
                }
            }
            return true;
        };

        for (const name of updateNames) {
            try {
                if (!applyChanges(await miDebugger.varUpdate(name, -1, -1))) {
                    break;
                }
            } catch (e) {
                this.cachedChangeList = undefined;
                break;
            }
        }
    }

    public createVariable(arg: VariableType, options?: any) {
        if (options) {
            return this.variableHandles.create(new ExtendedVariable(arg, options));
        } else {
            return this.variableHandles.create(arg);
        }
    }

    public findOrCreateVariable(varObj: VariableObject): number {
        let id = this.variableHandlesReverse.get(varObj.name);
        if (id === undefined) {
            id = this.createVariable(varObj);
            this.variableHandlesReverse.set(varObj.name, id);
        }
        return varObj.isCompound() ? id : 0;
    }

    private evaluateQ = new RequestQueue<DebugProtocol.EvaluateResponse, DebugProtocol.EvaluateArguments>();
    public evaluateRequest(
        r: DebugProtocol.EvaluateResponse, a: DebugProtocol.EvaluateArguments,
        miDebugger: MI2, session: GDBDebugSession, forceNoFrameId = false): Promise<void> {
        a.context = a.context || 'hover';
        if (a.context !== 'repl') {
            if (this.isBusy()) {
                this.busyError(r, a);
                return Promise.resolve();
            }
        }

        const doit = (
            response: DebugProtocol.EvaluateResponse, args: DebugProtocol.EvaluateArguments,
            _pendContinue: any, miDebugger: MI2, session: GDBDebugSession) => {
            return new Promise<void>(async (resolve) => {
                if (this.isBusy() && (a.context !== 'repl')) {
                    this.busyError(response, args);
                    resolve();
                    return;
                }

                // Spec says if 'frameId' is specified, evaluate in the scope specified or in the global scope. Well,
                // we don't have a way to specify global scope ... use floating variable.
                let threadId = session.stoppedThreadId || 1;
                let frameId = 0;
                if (forceNoFrameId) {
                    threadId = frameId = -1;
                    args.frameId = undefined;
                } else if (args.frameId !== undefined) {
                    [threadId, frameId] = decodeReference(args.frameId);
                }

                if (args.context !== 'repl') {
                    try {
                        const exp = args.expression;
                        const hasher = crypto.createHash('sha256');
                        hasher.update(exp);
                        if (!forceNoFrameId && (args.frameId !== undefined)) {
                            hasher.update(args.frameId.toString(16));
                        }
                        const exprName = hasher.digest('hex');
                        const varObjName = `${args.context}_${exprName}`;
                        let varObj: VariableObject;
                        let varId = this.variableHandlesReverse.get(varObjName);
                        let forceCreate = varId === undefined;
                        let updateError;
                        if (!forceCreate) {
                            try {
                                const cachedChange = this.cachedChangeList && this.cachedChangeList[varObjName];
                                let changelist;
                                if (cachedChange) {
                                    changelist = [];
                                } else if (this.cachedChangeList && (varId !== undefined)) {
                                    changelist = [];
                                } else {
                                    const changes = await miDebugger.varUpdate(varObjName, threadId, frameId);
                                    changelist = changes.result('changelist') ?? [];
                                }
                                for (const change of changelist) {
                                    const inScope = MINode.valueOf(change, 'in_scope');
                                    if (inScope === 'true') {
                                        const name = MINode.valueOf(change, 'name');
                                        const vId = this.variableHandlesReverse.get(name);
                                        const v = this.variableHandles.get(vId) as any;
                                        v.applyChanges(change);
                                        if (this.cachedChangeList) {
                                            this.cachedChangeList[name] = change;
                                        }
                                    } else {
                                        const msg = `${exp} currently not in scope`;
                                        await miDebugger.sendCommand(`var-delete ${varObjName}`);
                                        if (session.args.showDevDebugOutput) {
                                            session.handleMsg('log', `Expression ${msg}. Will try to create again\n`);
                                        }
                                        forceCreate = true;
                                        throw new Error(msg);
                                    }
                                }
                                varObj = this.variableHandles.get(varId) as any;
                                if (varObj && exp) {
                                    try {
                                        const addrExpr = exp.replace(/\\"/g, '"');
                                        const addrResp = await miDebugger.sendCommand(`data-evaluate-expression "&${addrExpr}"`);
                                        const addrValue = addrResp.result('value');
                                        if (addrValue && addrValue.startsWith('0x')) {
                                            varObj.address = addrValue;
                                        }
                                    } catch (e) {
                                        // Address might not be available for all variables
                                    }
                                }
                            } catch (err) {
                                updateError = err;
                            }
                        }
                        if (!this.isBusy() && (forceCreate || ((updateError instanceof MIError && updateError.message === 'Variable object not found')))) {
                            if (this.cachedChangeList) {
                                delete this.cachedChangeList[varObjName];
                            }
                            if (forceNoFrameId || (args.frameId === undefined)) {
                                varObj = await miDebugger.varCreate(0, exp, varObjName, '@');  // Create floating variable
                            } else {
                                varObj = await miDebugger.varCreate(0, exp, varObjName, '@', threadId, frameId);
                            }
                            varId = this.findOrCreateVariable(varObj);
                            varObj.exp = exp;
                            varObj.id = varId;
                        } else if (!varObj) {
                            throw updateError || new Error('live watch unknown error');
                        }

                        response.body = varObj.toProtocolEvaluateResponseBody();
                        response.success = true;
                        session.sendResponse(response);
                    } catch (err) {
                        if (this.isBusy()) {
                            this.busyError(response, args);
                        } else {
                            response.body = {
                                result: (args.context === 'hover') ? null : `<${err.toString()}>`,
                                variablesReference: 0
                            };
                            session.sendResponse(response);
                            if (session.args.showDevDebugOutput) {
                                session.handleMsg('stderr', args.context + ' ' + err.toString());
                            }
                        }
                        // this.sendErrorResponse(response, 7, err.toString());
                    } finally {
                        resolve();
                    }
                } else {        // This is an 'repl'
                    try {
                        miDebugger.sendUserInput(args.expression).then((output) => {
                            if (typeof output === 'undefined') {
                                response.body = {
                                    result: '',
                                    variablesReference: 0
                                };
                            } else {
                                response.body = {
                                    result: JSON.stringify(output),
                                    variablesReference: 0
                                };
                            }
                            session.sendResponse(response);
                            resolve();
                        }, (msg) => {
                            session.sendErrorResponsePub(response, 8, msg.toString());
                            resolve();
                        });
                    } catch (e) {
                        session.sendErrorResponsePub(response, 8, e.toString());
                        resolve();
                    }
                }
            });
        };

        return this.evaluateQ.add(doit, r, a, miDebugger, session);
    }

    public getCachedChilren(pVar: VariableObject, start?: number, count?: number): VariableObject[] | undefined {
        if (!this.cachedChangeList) { return undefined; }
        if (start !== undefined || count !== undefined) { return undefined; }
        const keys = Object.keys(pVar.children);
        if (keys.length === 0) { return undefined; }        // We don't have previous children, force a refresh
        const ret: VariableObject[] = [];
        for (const key of keys) {
            const gdbVaName = pVar.children[key];
            const childId = this.variableHandlesReverse.get(gdbVaName);
            if (childId === undefined) {
                return undefined;
            }
            const childObj = this.variableHandles.get(childId) as VariableObject;
            ret.push(childObj);
        }
        return ret;
    }

    public async variablesChildrenRequest(
        response: DebugProtocol.VariablesResponse, args: DebugProtocol.VariablesArguments,
        miDebugger: MI2, session: GDBDebugSession): Promise<void> {
        response.body = { variables: [] };
        if (!args.variablesReference) {
            // This should only be called to expand additional variable for a valid parent
            session.sendResponse(response);
            return;
        }
        const id = this.variableHandles.get(args.variablesReference);
        if (typeof id === 'object') {
            if (id instanceof VariableObject) {
                const pVar = id;

                // Variable members
                let children: VariableObject[];
                const childMap: { [name: string]: number } = {};
                try {
                    const requestStartedAt = Date.now();
                    const vars: DebugProtocol.Variable[] = [];
                    const requestedStart = args.start;
                    const requestedCount = args.count;
                    const isPagingRequest = requestedStart !== undefined || requestedCount !== undefined;
                    if (isPagingRequest) {
                        this.pagingLog(session, `variablesChildrenRequest parentExp=${pVar.exp} parentName=${pVar.name}`
                            + ` ref=${args.variablesReference} start=${requestedStart ?? '<none>'}`
                            + ` count=${requestedCount ?? '<none>'} numchild=${pVar.numchild} type=${pVar.type}`
                            + ` parentAddress=${pVar.address || '<none>'}`);
                    }
                    const cacheLookupStartedAt = Date.now();
                    children = this.getCachedChilren(pVar, requestedStart, requestedCount);
                    const cacheLookupMs = Date.now() - cacheLookupStartedAt;
                    const cacheHit = !!children;
                    let fetchMs = 0;
                    if (!children) {
                        const fetchStartedAt = Date.now();
                        children = await this.fetchChildrenPage(
                            miDebugger, args.variablesReference, id.name, pVar.address, pVar.type, requestedStart, requestedCount,
                            isPagingRequest ? (message) => this.pagingLog(session, message) : undefined);
                        fetchMs = Date.now() - fetchStartedAt;
                        pVar.hasMore = requestedStart !== undefined && pVar.numchild > 0
                            ? requestedStart + children.length < pVar.numchild
                            : !!(children as any).hasMore;
                        pVar.children = {};     // Clear in case type changed, dynamic variable, etc.
                    }

                    // Map children to protocol variables
                    const mapStartedAt = Date.now();
                    for (const child of children) {
                        if (!child.id) {
                            const varId = this.findOrCreateVariable(child);
                            child.id = varId;
                        }
                        if (/^\d+$/.test(child.exp)) {
                            child.fullExp = `${pVar.fullExp || pVar.exp}[${child.exp}]`;
                        } else {
                            let suffix = '.' + child.exp;
                            if (child.exp.startsWith('<anonymous')) {
                                const prev = childMap[child.exp];
                                if (prev) {
                                    childMap[child.exp] = prev + 1;
                                    child.exp += '#' + prev.toString(10);
                                }
                                childMap[child.exp] = 1;
                                suffix = '';
                            } else {
                                pVar.children[child.exp] = child.name;
                            }
                            child.fullExp = `${pVar.fullExp || pVar.exp}${suffix}`;
                        }
                        vars.push(child.toProtocolVariable());
                    }
                    const mapMs = Date.now() - mapStartedAt;

                    response.body = {
                        variables: vars
                    };
                    (response.body as any).hasMore = !!pVar.hasMore;
                    if (Number.isFinite(pVar.numchild)) {
                        (response.body as any).totalChildren = pVar.numchild;
                    }
                    if (isPagingRequest) {
                        this.pagingLog(session, `variablesChildrenResponse parentExp=${pVar.exp} ref=${args.variablesReference}`
                            + ` start=${requestedStart ?? '<none>'} count=${requestedCount ?? '<none>'}`
                            + ` children=${children.length} variables=${vars.length} pVarHasMore=${pVar.hasMore}`
                            + ` totalChildren=${Number.isFinite(pVar.numchild) ? pVar.numchild : '<none>'}`
                            + ` cacheHit=${cacheHit} cacheLookupMs=${cacheLookupMs} fetchMs=${fetchMs}`
                            + ` mapMs=${mapMs} totalMs=${Date.now() - requestStartedAt}`
                            + ` ${this.describeFetchProfile(children)}`
                            + ` ${this.describeChildren(children)}`);
                    }
                    session.sendResponse(response);
                } catch (err) {
                    const requestedStart = args.start;
                    const requestedCount = args.count;
                    if (requestedStart !== undefined || requestedCount !== undefined) {
                        this.pagingLog(session, `variablesChildrenError ref=${args.variablesReference}`
                            + ` start=${requestedStart ?? '<none>'} count=${requestedCount ?? '<none>'} error=${err}`);
                    }
                    session.sendErrorResponsePub(response, 1, `Could not expand variable: ${err}`);
                }
            } else if (id instanceof ExtendedVariable) {
                const variables: DebugProtocol.Variable[] = [];

                const varReq = id;
                if (varReq.options.arg) {
                    const strArr = [];
                    let argsPart = true;
                    let arrIndex = 0;
                    const submit = () => {
                        response.body = {
                            variables: strArr
                        };
                        session.sendResponse(response);
                    };
                    const addOne = async () => {
                        const variable = await miDebugger.evalExpression(JSON.stringify(`${varReq.name}+${arrIndex})`), -1, -1);
                        try {
                            const expanded = expandValue(this.createVariable.bind(this), variable.result('value'), varReq.name, variable);
                            if (!expanded) {
                                session.sendErrorResponsePub(response, 15, 'Could not expand variable');
                            } else {
                                if (typeof expanded === 'string') {
                                    if (expanded === '<nullptr>') {
                                        if (argsPart) {
                                            argsPart = false;
                                        } else {
                                            return submit();
                                        }
                                    } else if (expanded[0] !== '"') {
                                        strArr.push({
                                            name: '[err]',
                                            value: expanded,
                                            variablesReference: 0
                                        });
                                        return submit();
                                    }
                                    strArr.push({
                                        name: `[${(arrIndex++)}]`,
                                        value: expanded,
                                        variablesReference: 0
                                    });
                                    addOne();
                                } else {
                                    strArr.push({
                                        name: '[err]',
                                        value: expanded,
                                        variablesReference: 0
                                    });
                                    submit();
                                }
                            }
                        } catch (e) {
                            session.sendErrorResponsePub(response, 14, `Could not expand variable: ${e}`);
                        }
                    };
                    addOne();
                } else {
                    session.sendErrorResponsePub(response, 13, `Unimplemented variable request options: ${JSON.stringify(varReq.options)}`);
                }
            } else {
                response.body = {
                    variables: id
                };
                session.sendResponse(response);
            }
        } else {
            response.body = {
                variables: []
            };
            session.sendResponse(response);
        }
    }

    public async searchChildrenRequest(
        response: DebugProtocol.Response, args: any,
        miDebugger: MI2, session: GDBDebugSession): Promise<void> {
        const ref = args?.variablesReference;
        const query = (args?.query ?? '').toString();
        const buildIndex = !!args?.buildIndex;
        response.body = { matches: [], truncated: false, scanned: 0 };
        if (!ref || (!query && !buildIndex)) {
            session.sendResponse(response);
            return;
        }

        const id = this.variableHandles.get(ref);
        if (!(id instanceof VariableObject)) {
            session.sendResponse(response);
            return;
        }

        try {
            this.pagingLog(session, `searchChildrenRequest parentExp=${id.exp} parentName=${id.name}`
                + ` ref=${ref} query="${query}" maxResults=${args?.maxResults ?? '<none>'}`
                + ` windowSize=${args?.windowSize ?? '<none>'} totalChildren=${id.numchild}`
                + ` buildIndex=${buildIndex}`);
            const result = await miDebugger.varSearchChildren(
                ref,
                id.name,
                query,
                args?.maxResults ?? 100,
                args?.windowSize ?? 128,
                id.numchild,
                buildIndex);
            response.body = result;
            this.pagingLog(session, `searchChildrenResponse parentExp=${id.exp} ref=${ref}`
                + ` query="${query}" matches=${result.matches.length} scanned=${result.scanned}`
                + ` indexed=${result.indexed} cacheHit=${result.cacheHit} truncated=${result.truncated}`
                + ` first=${result.matches[0]?.name ?? '<none>'}/${result.matches[0]?.suggestedStart ?? '<none>'}`);
            session.sendResponse(response);
        } catch (err) {
            this.pagingLog(session, `searchChildrenError ref=${ref} query="${query}" error=${err}`);
            session.sendErrorResponsePub(response, 1, `Could not search variable children: ${err}`);
        }
    }

    private async fetchChildrenPage(
        miDebugger: MI2, variablesReference: number, name: string, parentAddress?: string, parentType?: string, start?: number, count?: number,
        pagingLog?: (message: string) => void): Promise<VariableObject[]> {
        if (count === 0) {
            pagingLog?.(`fetchChildrenPage skipped zero-count ref=${variablesReference} name=${name} start=${start ?? '<none>'}`);
            return [];
        }

        pagingLog?.(`fetchChildrenPage direct ref=${variablesReference} name=${name} start=${start ?? '<none>'} count=${count ?? '<none>'}`);
        const pageStartedAt = Date.now();
        const directStartedAt = Date.now();
        let children = await miDebugger.varListChildren(variablesReference, name, true, start, count, parentAddress, parentType);
        const directMs = Date.now() - directStartedAt;
        pagingLog?.(`fetchChildrenPage directResult ref=${variablesReference} name=${name} start=${start ?? '<none>'}`
            + ` count=${count ?? '<none>'} returned=${children.length} gdbHasMore=${!!(children as any).hasMore}`
            + ` directMs=${directMs} totalMs=${Date.now() - pageStartedAt}`
            + ` ${this.describeFetchProfile(children)}`
            + ` ${this.describeChildren(children)}`);
        if (children.length || start === undefined || start <= 0 || count === undefined || count <= 1) {
            return children;
        }

        pagingLog?.(`fetchChildrenPage emptyWithPositiveStart ref=${variablesReference} name=${name}`
            + ` start=${start} count=${count}; probing smaller counts`);
        let low = 1;
        let high = count - 1;
        let best: VariableObject[] = [];
        let trialCount = 0;
        const fallbackStartedAt = Date.now();
        while (low <= high) {
            const mid = Math.floor((low + high) / 2);
            const trialStartedAt = Date.now();
            const trial = await miDebugger.varListChildren(variablesReference, name, true, start, mid, parentAddress, parentType);
            trialCount++;
            pagingLog?.(`fetchChildrenPage trial ref=${variablesReference} name=${name} start=${start}`
                + ` count=${mid} returned=${trial.length} trialMs=${Date.now() - trialStartedAt}`);
            if (trial.length) {
                best = trial;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        children = best;
        (children as any).hasMore = false;
        pagingLog?.(`fetchChildrenPage fallbackResult ref=${variablesReference} name=${name} start=${start}`
            + ` requestedCount=${count} returned=${children.length} trials=${trialCount}`
            + ` fallbackMs=${Date.now() - fallbackStartedAt} totalMs=${Date.now() - pageStartedAt}`
            + ` ${this.describeChildren(children)}`);
        return children;
    }
}

export class LiveWatchMonitor {
    public miDebugger: MI2 | undefined;
    protected varHandler: VariablesHandler;
    constructor(private mainSession: GDBDebugSession) {
        this.varHandler = new VariablesHandler(
            (): boolean => false,
            (r: DebugProtocol.Response, a: any) => { }
        );
    }

    public setupEvents(mi2: MI2) {
        this.miDebugger = mi2;
        this.miDebugger.on('quit', this.quitEvent.bind(this));
        this.miDebugger.on('exited-normally', this.quitEvent.bind(this));
        this.miDebugger.on('msg', (type: string, msg: string) => {
            this.mainSession.handleMsg(type, 'LiveGDB: ' + msg);
        });

        /*
        Yes, we get all of these events and they seem to be harlmess
        const otherEvents = [
            'stopped',
            'signal-stop',
            'generic-stopped',
            'watchpoint',
            'watchpoint-scope',
            'step-end',
            'step-out-end',
            'running',
            'continue-failed',
            'thread-created',
            'thread-exited',
            'thread-selected',
            'thread-group-exited'
        ];
        for (const ev of otherEvents) {
            this.miDebugger.on(ev, (arg) => {
                this.mainSession.handleMsg(
                    'stderr', `Internal Error: Live watch GDB session received an unexpected event '${ev}' with arg ${arg?.toString() ?? '<empty>'}\n`);
            });
        }
        */
    }

    protected quitEvent() {
        // this.miDebugger = undefined;
    }

    public evaluateRequest(response: DebugProtocol.EvaluateResponse, args: DebugProtocol.EvaluateArguments): Promise<void> {
        return new Promise<void>((resolve) => {
            args.frameId = undefined;       // We don't have threads or frames here. We always evaluate in global context
            this.varHandler.evaluateRequest(response, args, this.miDebugger, this.mainSession, true).finally(() => {
                if (this.mainSession.args.showDevDebugOutput) {
                    this.mainSession.handleMsg('log', `LiveGBD: Evaluated ${args.expression}\n`);
                }
                resolve();
            });
        });
    }

    public async variablesRequest(response: DebugProtocol.VariablesResponse, args: DebugProtocol.VariablesArguments): Promise<void> {
        const ret = await this.varHandler.variablesChildrenRequest(response, args, this.miDebugger, this.mainSession);
        return ret;
    }

    public async searchVariablesRequest(response: DebugProtocol.Response, args: any): Promise<void> {
        const ret = await this.varHandler.searchChildrenRequest(response, args, this.miDebugger, this.mainSession);
        return ret;
    }

    // Calling this will also enable caching for the future of the session
    public async refreshLiveCache(args: RefreshAllArguments): Promise<void> {
        if (args.deleteAll) {
            await this.varHandler.clearCachedVars(this.miDebugger);
            return Promise.resolve();
        }
        return this.varHandler.refreshCachedChangeList(this.miDebugger, args);
    }

    public async setVariableRequest(response: DebugProtocol.Response, args: any): Promise<void> {
        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: setVariableRequest called - address='${args.address}', type='${args.type}'\n`);
        try {
            const name = args.name;
            const value = args.value;
            const expr = args.expr || name;
            const monitorExpr = this.normalizeMonitorExpression(expr);
            const address = args.address;  // Variable address for direct memory write
            const type = args.type;        // Variable type for determining size
            let bitfieldInfo;  // Bitfield information

            if (this.shouldUseMonitorWrite() && monitorExpr) {
                // Dynamically check if this is a bitfield and get its info
                const dynamicBitfieldInfo = await this.getBitfieldInfoForExpr(monitorExpr);
                if (dynamicBitfieldInfo) {
                    bitfieldInfo = dynamicBitfieldInfo;
                    // this.mainSession.handleMsg('stdout',
                    //     `DebugLiveWatch: [setVariableRequest] Dynamic bitfield info: ${JSON.stringify(bitfieldInfo)}\n`);
                }

                // Use monitor commands to write directly to memory
                const monitorAddress = await this.resolveMonitorWriteAddress(address, monitorExpr, bitfieldInfo);
                if (!monitorAddress) {
                    throw new Error(`Cannot resolve memory address for monitor write: ${monitorExpr}`);
                }
                const monitorType = await this.resolveMonitorWriteType(type, monitorExpr);
                await this.writeViaMonitor(monitorAddress, value, monitorType, monitorExpr, bitfieldInfo);
                response.body = { value: value };
                response.success = true;
                this.mainSession.sendResponse(response);

                if (this.mainSession.args.showDevDebugOutput) {
                    // this.mainSession.handleMsg('log', `DebugLiveWatch: Monitor write func writeViaMonitor ${address} = ${value}\n`);
                }
                return;
            }

            // For live watch, we use floating variables, so threadId and frameId are -1
            const threadId = -1;
            const frameId = -1;

            // Try to find the variable object name from the variable handles
            let varObjName = name;
            if (expr) {
                // Create a hash for the expression to find the variable object name
                const hasher = crypto.createHash('sha256');
                hasher.update(expr);
                const exprName = hasher.digest('hex');
                varObjName = `hover_${exprName}`;
            }

            // Check if this variable exists in our cache
            const varId = this.varHandler.variableHandlesReverse[varObjName];
            if (varId === undefined) {
                // Variable not found, try to create it first
                try {
                    const varObj = await this.miDebugger.varCreate(0, expr, varObjName, '@');
                    this.varHandler.findOrCreateVariable(varObj);
                } catch (e) {
                    throw new Error(`Variable ${name} not found`);
                }
            }

            // Perform the assignment using var-assign (original method)
            const res = await this.miDebugger.varAssign(varObjName, value, threadId, frameId);
            response.body = {
                value: res.result('value')
            };
            response.success = true;
            this.mainSession.sendResponse(response);
            /*
            if (this.mainSession.args.showDevDebugOutput) {
                this.mainSession.handleMsg('log', `LiveGDB: Set ${name} = ${value}\n`);
            }
            */
        } catch (err) {
            response.success = false;
            response.message = err.toString();
            this.mainSession.sendErrorResponsePub(response, 1, err.toString());
        }
    }

    /**
     * Check if we should use monitor commands for direct memory write.
     */
    private getMonitorWriteKind(): 'jlink' | 'openocd' | undefined {
        const servertype = (this.mainSession.args.servertype || '').toLowerCase();
        if (servertype === 'jlink') {
            return 'jlink';
        }
        if (servertype === 'openocd') {
            return 'openocd';
        }

        // External sessions are commonly used to connect to an already-running OpenOCD.
        // Prefer OpenOCD's mwb/mwh/mww commands so Live Watch writes still avoid GDB assignment.
        if (servertype === 'external') {
            return 'openocd';
        }

        return undefined;
    }

    private shouldUseMonitorWrite(): boolean {
        return this.getMonitorWriteKind() !== undefined;
    }

    private normalizeMonitorExpression(expr: any): string {
        if (typeof expr !== 'string') {
            return '';
        }
        let ret = expr.trim();
        if (/,[bdhonx]$/i.test(ret)) {
            ret = ret.substring(0, ret.length - 2).trim();
        }
        return ret;
    }

    private normalizeMonitorAddress(address: any): string {
        if (typeof address !== 'string') {
            return '';
        }
        const trimmed = address.trim();
        const spaceIndex = trimmed.indexOf(' ');
        const addressOnly = spaceIndex === -1 ? trimmed : trimmed.substring(0, spaceIndex);
        return /^0x[0-9a-f]+$/i.test(addressOnly) ? addressOnly : '';
    }

    private addAddressOffset(address: string, offset = 0): string {
        if (!offset) {
            return address;
        }
        return '0x' + (parseInt(address, 16) + offset).toString(16).toLowerCase();
    }

    private alignAddressDown(address: string, size?: number): string {
        if (!size || size <= 1) {
            return address;
        }
        const addr = parseInt(address, 16);
        return '0x' + (addr - (addr % size)).toString(16).toLowerCase();
    }

    private async resolveMonitorWriteAddress(address: any, expr: string, bitfieldInfo?: BitfieldInfo): Promise<string> {
        if (!expr) {
            return '';
        }

        if (bitfieldInfo?.isBitfield) {
            const bitfieldAddress = await this.resolveBitfieldContainerAddress(address, expr, bitfieldInfo);
            return bitfieldAddress;
        }

        const directAddress = this.normalizeMonitorAddress(address);
        if (directAddress) {
            return directAddress;
        }

        try {
            const addrResp = await this.miDebugger.sendCommand(`data-evaluate-expression "&(${expr})"`);
            return this.normalizeMonitorAddress(addrResp.result('value'));
        } catch (e) {
            return '';
        }
    }

    private async resolveBitfieldContainerAddress(address: any, expr: string, bitfieldInfo: BitfieldInfo): Promise<string> {
        const parentAddressExpr = this.getBitfieldParentAddressExpression(expr);
        if (parentAddressExpr) {
            try {
                const addrResp = await this.miDebugger.sendCommand(`data-evaluate-expression "${parentAddressExpr}"`);
                const parentAddress = this.normalizeMonitorAddress(addrResp.result('value'));
                if (parentAddress) {
                    return this.addAddressOffset(parentAddress, bitfieldInfo.containerOffset || 0);
                }
            } catch (e) {
                // Fall back to the provided address below. GDB cannot take a real address of a bitfield.
            }
        }

        const directAddress = this.normalizeMonitorAddress(address);
        return directAddress ? this.alignAddressDown(directAddress, bitfieldInfo.containerSize) : '';
    }

    private getBitfieldParentAddressExpression(expr: string): string {
        const dotIndex = expr.lastIndexOf('.');
        const arrowIndex = expr.lastIndexOf('->');
        const separatorIndex = Math.max(dotIndex, arrowIndex);

        if (separatorIndex === -1) {
            return '';
        }

        const parentExpr = expr.substring(0, separatorIndex);
        if (arrowIndex > dotIndex) {
            return `(${parentExpr})`;
        }
        return `&(${parentExpr})`;
    }

    private async resolveMonitorWriteType(type: any, expr: string): Promise<string> {
        if (typeof type === 'string' && type.trim()) {
            return type;
        }

        try {
            const escapedExpr = expr.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
            const result = await this.miDebugger.sendCommand(`interpreter-exec console "whatis ${escapedExpr}"`, false, true);
            const match = /type\s*=\s*([^\r\n]+)/.exec(result.output || '');
            return match ? match[1].trim() : '';
        } catch (e) {
            return '';
        }
    }

    private getMonitorWriteCommand(size: number): string {
        const writeSize = size === 1 || size === 2 ? size : 4;

        if (this.getMonitorWriteKind() === 'openocd') {
            if (writeSize === 1) {
                return 'mwb';
            }
            if (writeSize === 2) {
                return 'mwh';
            }
            return 'mww';
        }

        if (writeSize === 1) {
            return 'memU8';
        }
        if (writeSize === 2) {
            return 'memU16';
        }
        return 'memU32';
    }

    private async writeMemoryViaMonitor(size: number, address: string, value: number | bigint): Promise<void> {
        const monitorCmd = this.getMonitorWriteCommand(size);
        const writeSize = size === 1 || size === 2 ? size : 4;
        const rawValue = typeof value === 'bigint' ? value : BigInt(value >>> 0);
        const mask = (BigInt(1) << BigInt(writeSize * 8)) - BigInt(1);
        const hexValue = (rawValue & mask).toString(16).toLowerCase();
        const cmd = `monitor ${monitorCmd} ${address} 0x${hexValue}`;
        await this.miDebugger.sendCommand(`interpreter-exec console "${cmd}"`);
    }

    /**
     * Get bitfield information for an expression by parsing its type
     * @param expr Variable expression (e.g., 'GPIO->ODR', 'structVar.member')
     * @returns BitfieldInfo if the variable is a bitfield, null otherwise
     */
    private async getBitfieldInfoForExpr(expr: string): Promise<BitfieldInfo | null> {
        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Checking expr: ${expr}\n`);

        try {
            // Extract parent and member if expr contains '.' or '->'
            const dotIndex = expr.lastIndexOf('.');
            const arrowIndex = expr.lastIndexOf('->');
            const separatorIndex = Math.max(dotIndex, arrowIndex);

            if (separatorIndex === -1) {
                // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] No parent/child separator found\n`);
                return null;
            }

            // This is a member of a struct/union
            const parentExpr = expr.substring(0, separatorIndex);
            const memberName = expr.substring(separatorIndex + (arrowIndex !== -1 ? 2 : 1));

            // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Parent: ${parentExpr}, Member: ${memberName}\n`);

            // Get struct type info with offsets
            const structInfo = await this.miDebugger.getStructTypeInfo(parentExpr, memberName);
            if (!structInfo) {
                // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] No struct info found for ${parentExpr}\n`);
                return null;
            }

            const memberInfo = structInfo;
            if (memberInfo) {
                // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Member found: ${JSON.stringify(memberInfo)}\n`);

                // Check if this is a bitfield (has bitWidth)
                if (memberInfo.bitWidth !== undefined && memberInfo.bitWidth > 0) {
                    // this.mainSession.handleMsg('stdout',
                    //     `DebugLiveWatch: [getBitfieldInfoForExpr] Found bitfield: bitOffset=${memberInfo.bitOffset}, bitWidth=${memberInfo.bitWidth}\n`);

                    return {
                        isBitfield: true,
                        bitOffset: memberInfo.bitOffset || 0,
                        bitWidth: memberInfo.bitWidth,
                        containerOffset: memberInfo.containerOffset || 0,
                        containerSize: memberInfo.containerSize,
                        memberPath: expr
                    };
                } else {
                    // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Member is not a bitfield\n`);
                }
            } else {
                // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Member '${memberName}' not found in struct. \n`);
            }

            return null;
        } catch (e) {
            // this.mainSession.handleMsg('stderr', `DebugLiveWatch: [getBitfieldInfoForExpr] Error: ${e}\n`);
            return null;
        }
    }

    /**
     * Write to memory using GDB monitor commands via Live GDB session.
     * This avoids triggering watchpoints/SIGTRAP and keeps the target running.
     * @param address Memory address
     * @param value Value to write
     * @param type Variable type
     * @param expr Variable expression (e.g., 'structVar.memberName')
     * @param bitfieldInfo Optional bitfield information for read-modify-write
     */
    private async writeViaMonitor(address: string, value: string, type: string, expr?: string, bitfieldInfo?: BitfieldInfo): Promise<void> {
        // Extract actual address: take only the part before first space
        const spaceIndex = address.indexOf(' ');
        if (spaceIndex !== -1) {
            address = address.substring(0, spaceIndex);
        }

        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeViaMonitor] address=${address}, value=${value}, type=${type}, expr=${expr}\n`);
        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeViaMonitor] bitfieldInfo=${JSON.stringify(bitfieldInfo)}\n`);

        const lowerType = type.toLowerCase();
        const isFloat = lowerType.includes('float') && !lowerType.includes('double');
        const isDouble = lowerType.includes('double');

        let size = bitfieldInfo?.containerSize || 0;
        if (!size) {
            const sizeResult = await this.miDebugger.sendCommand(`data-evaluate-expression "sizeof(${expr})"`);
            size = parseInt(sizeResult.result('value'));
        }
        if (!size || isNaN(size)) {
            throw new Error(`Cannot resolve write size for monitor write: ${expr}`);
        }

        // Handle bitfield - need read-modify-write (bitfields can't be float)
        if (bitfieldInfo && bitfieldInfo.isBitfield && bitfieldInfo.bitOffset !== undefined && bitfieldInfo.bitWidth !== undefined) {
            const numValue = parseInt(value, value.startsWith('0x') ? 16 : 10);
            if (isNaN(numValue)) { throw new Error(`Invalid value: ${value}`); }
            // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeViaMonitor] BITFIELD detected, calling writeBitfield\n`);
            await this.writeBitfield(size, address, numValue, bitfieldInfo);
            return;
        }

        // Convert value to raw hex bytes based on type
        if (isFloat) {
            // float32: IEEE 754 single precision
            const floatVal = parseFloat(value);
            if (isNaN(floatVal)) { throw new Error(`Invalid float value: ${value}`); }
            const buf = new ArrayBuffer(4);
            new DataView(buf).setFloat32(0, floatVal, true); // little-endian
            await this.writeMemoryViaMonitor(4, address, new DataView(buf).getUint32(0, true));
            return;
        }

        if (isDouble) {
            // float64: IEEE 754 double precision, write as two 32-bit words (little-endian)
            const doubleVal = parseFloat(value);
            if (isNaN(doubleVal)) { throw new Error(`Invalid double value: ${value}`); }
            const buf = new ArrayBuffer(8);
            new DataView(buf).setFloat64(0, doubleVal, true); // little-endian
            const low32 = new DataView(buf).getUint32(0, true);
            const high32 = new DataView(buf).getUint32(4, true);

            await this.writeMemoryViaMonitor(4, address, low32);

            const addrHigh = '0x' + (parseInt(address, 16) + 4).toString(16).toLowerCase();
            await this.writeMemoryViaMonitor(4, addrHigh, high32);
            return;
        }

        // Integer types - use BigInt for proper 64-bit support
        let bigValue: bigint;
        try {
            if (value.startsWith('0x') || value.startsWith('0X')) {
                bigValue = BigInt(value);
            } else if (value.startsWith('0b') || value.startsWith('0B')) {
                bigValue = BigInt(value);
            } else if (value.startsWith('0') && value.length > 1) {
                bigValue = BigInt('0o' + value.substring(1));
            } else {
                bigValue = BigInt(value);
            }
        } catch (e) {
            throw new Error(`Invalid value: ${value}`);
        }

        const MASK32 = BigInt('0xFFFFFFFF');
        const low32 = Number(bigValue & MASK32) >>> 0;

        await this.writeMemoryViaMonitor(size, address, low32);

        if (size === 8) {
            const addrHigh = '0x' + (parseInt(address, 16) + 4).toString(16).toLowerCase();
            const high32 = Number((bigValue >> BigInt(32)) & MASK32) >>> 0;
            await this.writeMemoryViaMonitor(4, addrHigh, high32);
        }
    }

    /**
     * Write to a bitfield using read-modify-write
     * @param address Base address of the container
     * @param newValue New value for the bitfield
     * @param bitfieldInfo Bitfield information
     */
    private async writeBitfield(containerSize: number, address: string, newValue: number, bitfieldInfo: BitfieldInfo): Promise<void> {
        const bitOffset = bitfieldInfo.bitOffset;
        const bitWidth = bitfieldInfo.bitWidth;

        // this.mainSession.handleMsg('stdout',
        //     `DebugLiveWatch: [writeBitfield] addr=${address}, offset=${bitOffset}, width=${bitWidth}, value=${newValue}, containerSize=${containerSize}\n`);

        // Send read command using GDB MI data-read-memory
        const readCmd = `data-read-memory-bytes ${address} ${containerSize}`;
        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] Reading memory: ${readCmd}\n`);

        const readResp = await this.miDebugger.sendCommand(readCmd);
        const memoryBlock = readResp.result('memory')[0];
        const contentsEntry = memoryBlock.find((entry: any) => entry[0] === 'contents');
        if (!contentsEntry) { throw new Error('Failed to read memory contents'); }
        const memoryData = contentsEntry[1] as string;

        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] Raw memory data: ${memoryData}\n`);

        // Parse hex bytes to integer (little-endian)
        // i increments by 2 (2 hex chars per byte), so byte index = i/2, shift = i*4
        let currentValue = 0;
        for (let i = 0; i < memoryData.length; i += 2) {
            const byte = parseInt(memoryData.substr(i, 2), 16);
            currentValue |= (byte << i * 4);
        }

        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] Current container value = 0x${currentValue.toString(16)}\n`);

        // Step 2: Clear the target bitfield and set new value
        // Create mask for the bitfield
        const mask = ((1 << bitWidth) - 1) << bitOffset;
        const maskedValue = (newValue & ((1 << bitWidth) - 1)) << bitOffset;

        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] mask=0x${mask.toString(16)}, maskedValue=0x${maskedValue.toString(16)}\n`);

        // Clear target bits and set new value
        const newValueContainer = (currentValue & ~mask) | maskedValue;

        // this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] New container value = 0x${newValueContainer.toString(16)}\n`);

        const lowNewValueContainer = (newValueContainer >>> 0) & 0xFFFFFFFF;
        // Step 3: Write back the modified value
        await this.writeMemoryViaMonitor(containerSize, address, lowNewValueContainer);
        if (containerSize === 8) {
            const addrNum = parseInt(address, 16) + 4;
            const highAddr = '0x' + addrNum.toString(16).toLowerCase();
            const highNewValueContainer = (Math.floor(newValueContainer / 0x100000000) & 0xFFFFFFFF >>> 0);
            await this.writeMemoryViaMonitor(4, highAddr, highNewValueContainer);
        }
    }

    private quitting = false;
    public quit() {
        try {
            if (!this.quitting) {
                this.quitting = true;
                this.miDebugger.detach();
            }
        } catch (e) {
            console.error('LiveWatchMonitor.quit', e);
        }
    }
}

interface RefreshAllArguments {
    // Delete all gdb variables and the cache. This should be done when a live expression is deleted,
    // but otherwise, it is not needed
    deleteAll: boolean;
    // When present, refresh only the currently visible/expanded Live Watch chain.
    expressions?: string[];
    variableReferences?: number[];
}
