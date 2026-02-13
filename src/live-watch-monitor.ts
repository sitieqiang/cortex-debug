import { DebugProtocol } from '@vscode/debugprotocol';
import { Handles } from '@vscode/debugadapter';
import { MI2 } from './backend/mi2/mi2';
import { decodeReference, ExtendedVariable, GDBDebugSession, RequestQueue } from './gdb';
import { MIError, VariableObject, BitfieldInfo } from './backend/backend';
import * as crypto from 'crypto';
import { MINode } from './backend/mi_parse';
import { expandValue } from './backend/gdb_expansion';

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

    public async clearCachedVars(miDebugger: MI2) {
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

    public refreshCachedChangeList(miDebugger: MI2, resolve) {
        this.cachedChangeList = {};
        miDebugger.varUpdate('*', -1, -1).then((changes: MINode) => {
            const changelist = changes.result('changelist');
            for (const change of changelist || []) {
                const name = MINode.valueOf(change, 'name');
                this.cachedChangeList[name] = change;
                const inScope = MINode.valueOf(change, 'in_scope');
                const typeChanged = MINode.valueOf(change, 'type_changed');
                if ((inScope === 'false') || (typeChanged === 'true')) {
                    // If one of these conditions happened, abandon the entire cache. TODO: Optimize later
                    this.cachedChangeList = undefined;
                    break;
                }
                const vId = this.variableHandlesReverse.get(name);
                const v = this.variableHandles.get(vId) as any;
                v.applyChanges(change);
            }
        }).finally (() => {
            resolve();
        });
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

    public getCachedChilren(pVar: VariableObject): VariableObject[] | undefined {
        if (!this.cachedChangeList) { return undefined; }
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
                    let vars = [];
                    children = this.getCachedChilren(pVar);
                    if (children) {
                        for (const child of children) {
                            vars.push(child.toProtocolVariable());
                        }
                    } else {
                        children = await miDebugger.varListChildren(args.variablesReference, id.name, true);
                        pVar.children = {};     // Clear in case type changed, dynamic variable, etc.
                        vars = children.map((child) => {
                            const varId = this.findOrCreateVariable(child);
                            child.id = varId;
                            if (/^\d+$/.test(child.exp)) {
                                child.fullExp = `${pVar.fullExp || pVar.exp}[${child.exp}]`;
                            } else {
                                let suffix = '.' + child.exp;                   // A normal suffix
                                if (child.exp.startsWith('<anonymous')) {       // We can have duplicates!!
                                    const prev = childMap[child.exp];
                                    if (prev) {
                                        childMap[child.exp] = prev + 1;
                                        child.exp += '#' + prev.toString(10);
                                    }
                                    childMap[child.exp] = 1;
                                    suffix = '';    // Anonymous ones don't have a suffix. Have to use parent name
                                } else {
                                    // The full-name is not always derivable from the parent and child info. Esp. children
                                    // of anonymous stuff. Might as well store all of them or set-value will not work.
                                    pVar.children[child.exp] = child.name;
                                }
                                child.fullExp = `${pVar.fullExp || pVar.exp}${suffix}`;
                            }
                            return child.toProtocolVariable();
                        });
                    }

                    response.body = {
                        variables: vars
                    };
                    session.sendResponse(response);
                } catch (err) {
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

    // Calling this will also enable caching for the future of the session
    public async refreshLiveCache(args: RefreshAllArguments): Promise<void> {
        if (args.deleteAll) {
            await this.varHandler.clearCachedVars(this.miDebugger);
            return Promise.resolve();
        }
        return new Promise<void>((resolve) => {
            this.varHandler.refreshCachedChangeList(this.miDebugger, resolve);
        });
    }

    public async setVariableRequest(response: DebugProtocol.Response, args: any): Promise<void> {
        this.mainSession.handleMsg('stdout', `DebugLiveWatch: setVariableRequest called - address='${args.address}', type='${args.type}'\n`);
        try {
            const name = args.name;
            const value = args.value;
            const expr = args.expr;
            const address = args.address;  // Variable address for direct memory write
            const type = args.type;        // Variable type for determining size
            let bitfieldInfo ;  // Bitfield information

            // Check if we should use J-Link monitor commands for direct memory write
            // This avoids triggering watchpoints/SIGTRAP
            const useMonitorWrite = this.shouldUseMonitorWrite() && address && type;

            if (useMonitorWrite) {
                // Dynamically check if this is a bitfield and get its info
                if (expr) {
                    const dynamicBitfieldInfo = await this.getBitfieldInfoForExpr(expr);
                    if (dynamicBitfieldInfo) {
                        bitfieldInfo = dynamicBitfieldInfo;
                        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [setVariableRequest] Dynamic bitfield info: ${JSON.stringify(bitfieldInfo)}\n`);
                    }
                }

                // Use J-Link monitor commands to write directly to memory
                await this.writeViaMonitor(address, value, type, expr, bitfieldInfo);
                response.body = { value: value };
                response.success = true;
                this.mainSession.sendResponse(response);

                if (this.mainSession.args.showDevDebugOutput) {
                    this.mainSession.handleMsg('log', `DebugLiveWatch: Monitor write func writeViaMonitor ${address} = ${value}\n`);
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
                const crypto = require('crypto');
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

            if (this.mainSession.args.showDevDebugOutput) {
                this.mainSession.handleMsg('log', `LiveGDB: Set ${name} = ${value}\n`);
            }
        } catch (err) {
            response.success = false;
            response.message = err.toString();
            this.mainSession.sendErrorResponsePub(response, 1, err.toString());
        }
    }

    /**
     * Check if we should use J-Link monitor commands for memory write
     */
    private shouldUseMonitorWrite(): boolean {
        // Check if the servertype is jlink
        return this.mainSession.args.servertype === 'jlink';
    }

    /**
     * Get bitfield information for an expression by parsing its type
     * @param expr Variable expression (e.g., 'GPIO->ODR', 'structVar.member')
     * @returns BitfieldInfo if the variable is a bitfield, null otherwise
     */
    private async getBitfieldInfoForExpr(expr: string): Promise<BitfieldInfo | null> {
        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Checking expr: ${expr}\n`);

        try {
            // Extract parent and member if expr contains '.' or '->'
            const dotIndex = expr.lastIndexOf('.');
            const arrowIndex = expr.lastIndexOf('->');
            const separatorIndex = Math.max(dotIndex, arrowIndex);

            if (separatorIndex === -1) {
                this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] No parent/child separator found\n`);
                return null;
            }

            // This is a member of a struct/union
            const parentExpr = expr.substring(0, separatorIndex);
            const memberName = expr.substring(separatorIndex + (arrowIndex !== -1 ? 2 : 1));

            this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Parent: ${parentExpr}, Member: ${memberName}\n`);



            // Get struct type info with offsets
            const structInfo = await this.miDebugger.getStructTypeInfo(parentExpr,memberName);
            if (!structInfo) {
                this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] No struct info found for ${parentExpr}\n`);
                return null;
            }


            const memberInfo = structInfo;
            if (memberInfo) {
                this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Member found: ${JSON.stringify(memberInfo)}\n`);

                // Check if this is a bitfield (has bitWidth)
                if (memberInfo.bitWidth !== undefined && memberInfo.bitWidth > 0) {


                    this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Found bitfield: bitOffset=${memberInfo.bitOffset}, bitWidth=${memberInfo.bitWidth}\n`);

                    return {
                        isBitfield: true,
                        bitOffset: memberInfo.bitOffset || 0,
                        bitWidth: memberInfo.bitWidth,
                        memberPath: expr
                    };
                } else {
                    this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Member is not a bitfield\n`);
                }
            } else {
                this.mainSession.handleMsg('stdout', `DebugLiveWatch: [getBitfieldInfoForExpr] Member '${memberName}' not found in struct. \n`);
            }

            return null;
        } catch (e) {
            this.mainSession.handleMsg('stderr', `DebugLiveWatch: [getBitfieldInfoForExpr] Error: ${e}\n`);
            return null;
        }
    }

    /**
     * Write to memory using GDB MI commands via Live GDB session
     * This avoids triggering watchpoints/SIGTRAP
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

        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeViaMonitor] address=${address}, value=${value}, type=${type}, expr=${expr}\n`);
        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeViaMonitor] bitfieldInfo=${JSON.stringify(bitfieldInfo)}\n`);

        const lowerType = type.toLowerCase();
        const isFloat = lowerType.includes('float') && !lowerType.includes('double');
        const isDouble = lowerType.includes('double');

        // Get size via GDB sizeof
        const sizeResult = await this.miDebugger.sendCommand(`data-evaluate-expression "sizeof(${expr})"`);
        const size = parseInt(sizeResult.result('value'));

        // Handle bitfield - need read-modify-write (bitfields can't be float)
        if (bitfieldInfo && bitfieldInfo.isBitfield && bitfieldInfo.bitOffset !== undefined && bitfieldInfo.bitWidth !== undefined) {
            const numValue = parseInt(value, value.startsWith('0x') ? 16 : 10);
            if (isNaN(numValue)) { throw new Error(`Invalid value: ${value}`); }
            this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeViaMonitor] BITFIELD detected, calling writeBitfield\n`);
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
            const hexValue = new DataView(buf).getUint32(0, true).toString(16).toLowerCase();
            const cmd = `monitor memU32 ${address} 0x${hexValue}`;
            this.mainSession.handleMsg('stdout', `DebugLiveWatch: [direct write float] cmd='${cmd}'\n`);
            await this.miDebugger.sendCommand(`interpreter-exec console "${cmd}"`);
            return;
        }

        if (isDouble) {
            // float64: IEEE 754 double precision, write as two memU32 (little-endian)
            const doubleVal = parseFloat(value);
            if (isNaN(doubleVal)) { throw new Error(`Invalid double value: ${value}`); }
            const buf = new ArrayBuffer(8);
            new DataView(buf).setFloat64(0, doubleVal, true); // little-endian
            const low32 = new DataView(buf).getUint32(0, true);
            const high32 = new DataView(buf).getUint32(4, true);

            const cmdLow = `monitor memU32 ${address} 0x${low32.toString(16).toLowerCase()}`;
            this.mainSession.handleMsg('stdout', `DebugLiveWatch: [direct write double low] cmd='${cmdLow}'\n`);
            await this.miDebugger.sendCommand(`interpreter-exec console "${cmdLow}"`);

            const addrHigh = '0x' + (parseInt(address, 16) + 4).toString(16).toLowerCase();
            const cmdHigh = `monitor memU32 ${addrHigh} 0x${high32.toString(16).toLowerCase()}`;
            this.mainSession.handleMsg('stdout', `DebugLiveWatch: [direct write double high] cmd='${cmdHigh}'\n`);
            await this.miDebugger.sendCommand(`interpreter-exec console "${cmdHigh}"`);
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
        const hexValue = low32.toString(16).toLowerCase();

        let monitorCmd = 'memU32';
        if (size === 1) { monitorCmd = 'memU8'; }
        else if (size === 2) { monitorCmd = 'memU16'; }

        const cmd = `monitor ${monitorCmd} ${address} 0x${hexValue}`;
        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [direct write] cmd='${cmd}'\n`);
        await this.miDebugger.sendCommand(`interpreter-exec console "${cmd}"`);

        if (size === 8) {
            const addrHigh = '0x' + (parseInt(address, 16) + 4).toString(16).toLowerCase();
            const high32 = Number((bigValue >> BigInt(32)) & MASK32) >>> 0;
            const highHexValue = high32.toString(16).toLowerCase();
            const writeCmd = `monitor memU32 ${addrHigh} 0x${highHexValue}`;
            this.mainSession.handleMsg('stdout', `DebugLiveWatch: [direct write 64-bit high] Writing: ${writeCmd}\n`);
            await this.miDebugger.sendCommand(`interpreter-exec console "${writeCmd}"`);
        }
    }

    /**
     * Write to a bitfield using read-modify-write
     * @param address Base address of the container
     * @param newValue New value for the bitfield
     * @param bitfieldInfo Bitfield information
     */
    private async writeBitfield(containerSize:number,address: string, newValue: number, bitfieldInfo: BitfieldInfo): Promise<void> {
        const bitOffset = bitfieldInfo.bitOffset!;
        const bitWidth = bitfieldInfo.bitWidth!;

        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] addr=${address}, offset=${bitOffset}, width=${bitWidth}, value=${newValue}, containerSize=${containerSize}\n`);

        // Step 1: Read current value from memory
        let monitorCmd = 'memU32';
        if (containerSize === 1) {
            monitorCmd = 'memU8';
        } else if (containerSize === 2) {
            monitorCmd = 'memU16';
        }

        // Send read command using GDB MI data-read-memory
        const readCmd = `data-read-memory-bytes ${address} ${containerSize}`;
        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] Reading memory: ${readCmd}\n`);

        const readResp = await this.miDebugger.sendCommand(readCmd);
        const memoryBlock = readResp.result('memory')[0];
        const contentsEntry = memoryBlock.find((entry: any) => entry[0] === 'contents');
        if (!contentsEntry) { throw new Error('Failed to read memory contents'); }
        const memoryData = contentsEntry[1] as string;

        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] Raw memory data: ${memoryData}\n`);

        // Parse hex bytes to integer (little-endian)
        // i increments by 2 (2 hex chars per byte), so byte index = i/2, shift = i*4
        let currentValue = 0;
        for (let i = 0; i < memoryData.length; i += 2) {
            const byte = parseInt(memoryData.substr(i, 2), 16);
            currentValue |= (byte << i*4);
        }

        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] Current container value = 0x${currentValue.toString(16)}\n`);

        // Step 2: Clear the target bitfield and set new value
        // Create mask for the bitfield
        const mask = ((1 << bitWidth) - 1) << bitOffset;
        const maskedValue = (newValue & ((1 << bitWidth) - 1)) << bitOffset;

        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] mask=0x${mask.toString(16)}, maskedValue=0x${maskedValue.toString(16)}\n`);

        // Clear target bits and set new value
        const newValueContainer = (currentValue & ~mask) | maskedValue;

        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] New container value = 0x${newValueContainer.toString(16)}\n`);

        const lowNewValueContainer = (newValueContainer>>>0) & 0xFFFFFFFF;
        // Step 3: Write back the modified value
        const hexValue = (lowNewValueContainer >>> 0).toString(16).toLowerCase();
        const writeCmd = `monitor ${monitorCmd} ${address} 0x${hexValue}`;
        this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield] Writing: ${writeCmd}\n`);
        await this.miDebugger.sendCommand(`interpreter-exec console "${writeCmd}"`);
        if (containerSize === 8) {
            const addrNum = parseInt(address, 16) + 4;
            const highAddr = '0x' + addrNum.toString(16).toLowerCase();
            const highNewValueContainer = (Math.floor(newValueContainer / 0x100000000) & 0xFFFFFFFF>>>0);
            const highHexValue = (highNewValueContainer >>> 0).toString(16).toLowerCase();
            const highWriteCmd = `monitor memU32 ${highAddr} 0x${highHexValue}`;
            this.mainSession.handleMsg('stdout', `DebugLiveWatch: [writeBitfield 64-bit high] Writing: ${highWriteCmd}\n`);
            await this.miDebugger.sendCommand(`interpreter-exec console "${highWriteCmd}"`);
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
}
