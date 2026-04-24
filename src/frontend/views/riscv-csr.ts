import {
    TreeItem, TreeDataProvider, EventEmitter, Event, TreeItemCollapsibleState,
    ProviderResult, DebugSession, window, commands
} from 'vscode';
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { BaseNode } from './nodes/basenode';

export interface CsrBitFieldDef {
    name: string;
    size: number;
    start: number;
    enums: { name: string; value: number }[];
}

export interface CsrRegisterDef {
    name: string;
    size: number;
    address: number;
    access: string;
    bitFields: CsrBitFieldDef[];
}

export interface CsrGroupDef {
    name: string;
    registers: CsrRegisterDef[];
    defaultOpen: boolean;
    defaultVisible: boolean;
}

function parseXmlAttributes(tag: string): { [key: string]: string } {
    const attrs: { [key: string]: string } = {};
    const regex = /(\w+)="([^"]*)"/g;
    let match;
    while ((match = regex.exec(tag)) !== null) {
        attrs[match[1]] = match[2];
    }
    return attrs;
}

export function parseCsrXml(content: string): CsrGroupDef[] {
    const groups: CsrGroupDef[] = [];
    content = content.replace(/<!DOCTYPE[^>]*>/, '');

    const groupRegex = /<RegisterGroup([^>]*)>([\s\S]*?)<\/RegisterGroup>/g;
    let groupMatch;
    while ((groupMatch = groupRegex.exec(content)) !== null) {
        const groupAttrs = parseXmlAttributes(groupMatch[1]);
        const groupName = groupAttrs['name'] || 'Unknown';
        const defaultOpen = groupAttrs['default_open'] === 'Yes';
        const defaultVisible = groupAttrs['default_visible'] !== 'No';
        const group: CsrGroupDef = { name: groupName, registers: [], defaultOpen, defaultVisible };

        const registerContent = groupMatch[2];
        const registerRegex = /<Register([^>]*)\/?>(?:([\s\S]*?)<\/Register>)?/g;
        let regMatch;
        while ((regMatch = registerRegex.exec(registerContent)) !== null) {
            const regAttrs = parseXmlAttributes(regMatch[1]);
            const regName = regAttrs['name'];
            if (!regName) { continue; }

            const size = parseInt(regAttrs['size'] || '4', 10);
            const start = parseInt(regAttrs['start'] || '0', 0); // auto-detect base
            const access = regAttrs['access'] || 'ReadWrite';

            const reg: CsrRegisterDef = {
                name: regName,
                size,
                address: start,
                access,
                bitFields: []
            };

            const regContent = regMatch[2] || '';
            const bitFieldRegex = /<BitField([^>]*)\/?>(?:([\s\S]*?)<\/BitField>)?/g;
            let bfMatch;
            while ((bfMatch = bitFieldRegex.exec(regContent)) !== null) {
                const bfAttrs = parseXmlAttributes(bfMatch[1]);
                const bfName = bfAttrs['name'];
                if (!bfName) { continue; }

                const bfSize = parseInt(bfAttrs['size'] || '1', 10);
                const bfStart = parseInt(bfAttrs['start'] || '0', 10);

                const bitField: CsrBitFieldDef = {
                    name: bfName,
                    size: bfSize,
                    start: bfStart,
                    enums: []
                };

                const bfContent = bfMatch[2] || '';
                const enumRegex = /<Enum([^>]*)\/>/g;
                let enumMatch;
                while ((enumMatch = enumRegex.exec(bfContent)) !== null) {
                    const enumAttrs = parseXmlAttributes(enumMatch[1]);
                    if (enumAttrs['name'] && enumAttrs['value'] !== undefined) {
                        bitField.enums.push({
                            name: enumAttrs['name'],
                            value: parseInt(enumAttrs['value'], 10)
                        });
                    }
                }

                reg.bitFields.push(bitField);
            }

            group.registers.push(reg);
        }

        if (group.registers.length > 0 && group.defaultVisible) {
            groups.push(group);
        }
    }

    return groups;
}

// ---- Tree Nodes ----

export abstract class CsrNode extends BaseNode {
    constructor(parent?: CsrNode) {
        super(parent);
    }
}

export class CsrGroupNode extends CsrNode {
    public expanded = false;
    constructor(parent: CsrNode | undefined, public readonly def: CsrGroupDef, public readonly children: CsrRegisterNode[]) {
        super(parent);
    }

    public getTreeItem(): TreeItem | Promise<TreeItem> {
        const state = this.children.length > 0
            ? (this.expanded ? TreeItemCollapsibleState.Expanded : TreeItemCollapsibleState.Collapsed)
            : TreeItemCollapsibleState.None;
        const item = new TreeItem(this.def.name, state);
        item.contextValue = 'csrGroup';
        item.tooltip = `${this.def.name} (${this.children.length} registers)`;
        return item;
    }

    public getChildren(): CsrNode[] {
        return this.children;
    }

    public getCopyValue(): string | undefined {
        return undefined;
    }
}

export class CsrRegisterNode extends CsrNode {
    public value = '';
    public prevValue = '';
    public expanded = false;
    public updating = false;

    constructor(parent: CsrNode | undefined, public readonly def: CsrRegisterDef) {
        super(parent);
    }

    public getTreeItem(): TreeItem | Promise<TreeItem> {
        const hasChildren = this.def.bitFields.length > 0;
        const state = hasChildren
            ? (this.expanded ? TreeItemCollapsibleState.Expanded : TreeItemCollapsibleState.Collapsed)
            : TreeItemCollapsibleState.None;

        const displayValue = this.value || (this.updating ? '...' : '');
        const labelStr = displayValue ? `${this.def.name} = ${displayValue}` : this.def.name;
        const label: vscode.TreeItemLabel = {
            label: labelStr
        };
        if (this.prevValue && this.value && this.prevValue !== this.value) {
            label.highlights = [[this.def.name.length + 3, labelStr.length]];
        }

        const item = new TreeItem(label, state);
        item.contextValue = this.def.access === 'Readonly' ? 'csrRegisterReadonly' : 'csrRegister';
        const addrHex = this.def.address.toString(16).toUpperCase().padStart(4, '0');
        item.tooltip = `Address: 0x${addrHex}\nSize: ${this.def.size * 8} bits\nAccess: ${this.def.access}`;
        if (this.def.access !== 'Readonly') {
            item.command = {
                command: 'cortex-debug.riscvCsr.editValue',
                title: 'Edit CSR Value',
                arguments: [this]
            };
        }
        return item;
    }

    public getChildren(): CsrNode[] {
        if (!this.value || this.value === 'N/A') {
            return [];
        }
        const valNum = parseInt(this.value.replace(/^0x/i, ''), 16);
        if (isNaN(valNum)) {
            return [];
        }
        return this.def.bitFields.map((bf) => new CsrBitFieldNode(this, bf, valNum));
    }

    public getCopyValue(): string | undefined {
        return this.value;
    }
}

export class CsrBitFieldNode extends CsrNode {
    constructor(parent: CsrNode, public readonly def: CsrBitFieldDef, public readonly registerValue: number) {
        super(parent);
    }

    public getTreeItem(): TreeItem | Promise<TreeItem> {
        const mask = ((1 << this.def.size) - 1);
        const val = (this.registerValue >> this.def.start) & mask;
        let enumStr = '';
        if (this.def.enums.length > 0) {
            const enumMatch = this.def.enums.find((e) => e.value === val);
            if (enumMatch) {
                enumStr = ` (${enumMatch.name})`;
            }
        }
        const label = `${this.def.name}[${this.def.start + this.def.size - 1}:${this.def.start}] = ${val}${enumStr}`;
        const item = new TreeItem(label, TreeItemCollapsibleState.None);
        item.contextValue = 'csrBitField';
        item.tooltip = `BitField: ${this.def.name}\nStart: ${this.def.start}\nSize: ${this.def.size} bits`;
        return item;
    }

    public getChildren(): CsrNode[] {
        return [];
    }

    public getCopyValue(): string | undefined {
        const mask = ((1 << this.def.size) - 1);
        const val = (this.registerValue >> this.def.start) & mask;
        return val.toString();
    }
}

// ---- Provider ----

export class RiscvCsrProvider implements TreeDataProvider<CsrNode> {
    private _onDidChangeTreeData: EventEmitter<CsrNode | undefined> = new EventEmitter<CsrNode | undefined>();
    public readonly onDidChangeTreeData: Event<CsrNode | undefined> = this._onDidChangeTreeData.event;

    private groups: CsrGroupNode[] = [];
    private xmlGroups: CsrGroupDef[] = [];
    private session: DebugSession | undefined;
    private pendingRefresh = false;

    constructor() {
    }

    public loadXml(xmlPath: string): void {
        this.xmlGroups = [];
        this.groups = [];
        if (!xmlPath) {
            console.log('[RISCV-CSR] riscvCsrFile not configured');
            return;
        }
        if (!fs.existsSync(xmlPath)) {
            console.error('[RISCV-CSR] XML file not found:', xmlPath);
            window.showWarningMessage(`RISC-V CSR XML file not found: ${xmlPath}`);
            return;
        }
        try {
            const content = fs.readFileSync(xmlPath, 'utf-8');
            this.xmlGroups = parseCsrXml(content);
            this.groups = this.xmlGroups.map((g) => {
                const regNodes = g.registers.map((r) => new CsrRegisterNode(undefined, r));
                const groupNode = new CsrGroupNode(undefined, g, regNodes);
                groupNode.expanded = g.defaultOpen;
                return groupNode;
            });
            const totalRegs = this.groups.reduce((sum, g) => sum + g.children.length, 0);
            console.log(`[RISCV-CSR] Loaded ${this.groups.length} groups, ${totalRegs} registers from ${xmlPath}`);
        } catch (e) {
            console.error('[RISCV-CSR] Failed to parse XML:', e);
            window.showErrorMessage(`Failed to parse RISC-V CSR XML: ${e}`);
        }
    }

    public getTreeItem(element: CsrNode): TreeItem | Promise<TreeItem> {
        return element.getTreeItem();
    }

    public getChildren(element?: CsrNode): ProviderResult<CsrNode[]> {
        if (!element) {
            return this.groups;
        }
        return element.getChildren();
    }

    public setSession(session: DebugSession | undefined): void {
        this.session = session;
        if (!session) {
            this.clearValues();
            this.fire();
        }
    }

    public clearValues(): void {
        for (const g of this.groups) {
            for (const r of g.children) {
                r.value = '';
                r.prevValue = '';
            }
        }
    }

    public invalidateExpandedValues(): void {
        for (const g of this.groups) {
            if (g.expanded) {
                for (const r of g.children) {
                    r.prevValue = '';
                    r.value = '';
                }
            }
        }
        this.fire();
    }

    public refreshAll(): void {
        if (!this.session) { return; }
        for (const g of this.groups) {
            if (g.expanded) {
                this.refreshGroup(g);
            }
        }
        this.fire();
    }

    public refreshGroup(group: CsrGroupNode): void {
        if (!this.session) { return; }
        const registers = group.children;
        for (const reg of registers) {
            reg.updating = true;
        }
        this.fire();
    }

    public async readRegister(reg: CsrRegisterNode): Promise<void> {
        if (!this.session) { return; }
        reg.updating = true;
        this.fire(reg);
        try {
            const result = await this.session.customRequest('read-csr', { addr: reg.def.address, name: reg.def.name });
            reg.prevValue = reg.value;
            reg.value = (result && result.value) ? result.value : 'N/A';
        } catch (e) {
            reg.value = 'N/A';
        }
        reg.updating = false;
        this.fire(reg);
    }

    public async writeRegister(reg: CsrRegisterNode, newValue: string): Promise<boolean> {
        if (!this.session) { return false; }
        if (reg.def.access === 'Readonly') {
            window.showWarningMessage(`Register ${reg.def.name} is read-only`);
            return false;
        }
        try {
            const result = await this.session.customRequest('write-csr', { addr: reg.def.address, value: newValue });
            if (result && result.success) {
                await this.readRegister(reg);
                return true;
            } else {
                window.showErrorMessage(`Failed to write ${reg.def.name}: ${result?.message || 'Unknown error'}`);
                return false;
            }
        } catch (e) {
            window.showErrorMessage(`Failed to write ${reg.def.name}: ${e}`);
            return false;
        }
    }

    public fire(node?: CsrNode): void {
        this._onDidChangeTreeData.fire(node);
    }

    public expandGroup(group: CsrGroupNode): void {
        group.expanded = true;
        if (this.session) {
            this.refreshGroup(group);
        }
    }

    public async refreshRegisterIfNeeded(reg: CsrRegisterNode): Promise<void> {
        if (!this.session) { return; }
        await this.readRegister(reg);
    }

    public collapseGroup(group: CsrGroupNode): void {
        group.expanded = false;
        for (const r of group.children) {
            r.prevValue = '';
            r.value = '';
        }
        this.fire();
    }

    public expandRegister(reg: CsrRegisterNode): void {
        reg.expanded = true;
    }

    public collapseRegister(reg: CsrRegisterNode): void {
        reg.expanded = false;
    }

    public async editValue(node: CsrRegisterNode): Promise<void> {
        if (!this.session) {
            window.showWarningMessage('No active debug session');
            return;
        }
        if (node.def.access === 'Readonly') {
            window.showWarningMessage(`Register ${node.def.name} is read-only`);
            return;
        }
        const current = node.value || '0x0';
        const result = await window.showInputBox({
            placeHolder: 'Enter new value (hex or decimal)',
            ignoreFocusOut: true,
            value: current,
            prompt: `Edit ${node.def.name} (0x${node.def.address.toString(16).toUpperCase().padStart(4, '0')})`,
            validateInput: (value: string) => {
                if (!value || value.trim() === '') {
                    return 'Value cannot be empty';
                }
                return null;
            }
        });
        if (result !== undefined && result !== current) {
            await this.writeRegister(node, result.trim());
        }
    }
}
