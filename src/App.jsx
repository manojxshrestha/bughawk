import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import TopBar from './components/Shell/TopBar.jsx';
import Sidebar from './components/Shell/Sidebar.jsx';
import CommandPalette from './components/Shell/CommandPalette.jsx';
import ErrorBoundary from './components/Shell/ErrorBoundary.jsx';
import ProjectModal from './components/Sidebar/ProjectModal.jsx';

const Dashboard = lazy(() => import('./components/Dashboard/Dashboard.jsx'));
const SubdomainTab = lazy(() => import('./components/SubdomainTab/SubdomainTab.jsx'));
const ReconUrlParser = lazy(() => import('./components/UrlParser/ReconUrlParser.jsx'));
const JsReconTab = lazy(() => import('./components/JsRecon/JsReconTab.jsx'));
const PortTab = lazy(() => import('./components/PortTab/PortTab.jsx'));
const ScopeTab = lazy(() => import('./components/ScopeTab/ScopeTab.jsx'));
const AssetsTab = lazy(() => import('./components/AssetsTab/AssetsTab.jsx'));
const SurfaceTab = lazy(() => import('./components/Surface/SurfaceTab.jsx'));
const WordlistsTab = lazy(() => import('./components/Wordlists/WordlistsTab.jsx'));
const DorksTab = lazy(() => import('./components/Dorks/DorksTab.jsx'));
const JwtDecoderTab = lazy(() => import('./components/JwtDecoder/JwtDecoderTab.jsx'));
const HttpAnalyzerTab = lazy(() => import('./components/HttpAnalyzer/HttpAnalyzerTab.jsx'));
const FindingsTab = lazy(() => import('./components/Findings/FindingsTab.jsx'));
const TechStackTab = lazy(() => import('./components/TechStack/TechStackTab.jsx'));
const NotebookTab = lazy(() => import('./components/Notebook/NotebookTab.jsx'));
const SettingsTab = lazy(() => import('./components/Settings/SettingsTab.jsx'));
const ProjectImportModal = lazy(() => import('./components/ProjectImport/ProjectImportModal.jsx'));
import { useProjects } from './hooks/useProjects.js';
import { useSubdomains } from './hooks/useSubdomains.js';
import { usePorts } from './hooks/usePorts.js';
import { useTheme } from './hooks/useTheme.js';
import { useProjectValue } from './hooks/useProjectValue.js';
import { KEYS } from './lib/storage.js';
import { recordSnapshot } from './lib/events.js';
import { DEFAULT_KEYWORDS } from './lib/smartflag.js';
import { scopeOf } from './lib/scope.js';

export default function App() {
  const { theme, toggleTheme } = useTheme();

  const {
    projects,
    activeId,
    activeProject,
    isLoading: projectsLoading,
    createProject,
    renameProject,
    deleteProject,
    switchProject,
    updateProjectMeta,
  } = useProjects();

  const subs = useSubdomains(activeId, updateProjectMeta);
  const ports = usePorts(activeId, updateProjectMeta);
  const [notes, setNotes] = useProjectValue(activeId, KEYS.notes, '');
  const [keywords, setKeywords] = useProjectValue(activeId, KEYS.keywords, DEFAULT_KEYWORDS);
  const [scopeRules, setScopeRules] = useProjectValue(activeId, KEYS.scope, []);
  const [assets, setAssets] = useProjectValue(activeId, KEYS.assets, { subdomains: [], urls: [], jsfiles: [] });
  // Stable matcher: host -> 'in' | 'out' | 'unknown'. Recreated only when rules change.
  const scopeStatus = useMemo(() => (host) => scopeOf(host, scopeRules), [scopeRules]);

  const [activeTab, setActiveTab] = useState('dashboard');
  const [findingDraft, setFindingDraft] = useState(null); // prefill carried Notebook -> Findings
  const [modal, setModal] = useState(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [toast, setToast] = useState(null);
  const [focusNewIds, setFocusNewIds] = useState(null);

  const handleTabChange = useCallback((tab) => {
    setActiveTab(tab);
  }, []);

  const viewNew = useCallback((ids) => {
    setFocusNewIds(new Set(ids));
    setActiveTab('subdomains');
  }, []);
  const clearFocusNew = useCallback(() => setFocusNewIds(null), []);
  // Drop the focus filter when switching project.
  useEffect(() => { setFocusNewIds(null); }, [activeId]);

  // Auto-snapshot the attack surface after every subs/ports change (debounced),
  // so the change feed / resurrection / churn fill in without manual snapshots.
  useEffect(() => {
    if (!activeId) return undefined;
    const t = setTimeout(() => { recordSnapshot(activeId, subs.records, ports.records); }, 1000);
    return () => clearTimeout(t);
  }, [activeId, subs.records, ports.records]);

  const showToast = useCallback((msg) => setToast(msg), []);

  // Listen for storage errors and surface them to the user.
  useEffect(() => {
    const handler = (e) => showToast(e.detail);
    window.addEventListener('storage-error', handler);
    return () => window.removeEventListener('storage-error', handler);
  }, [showToast]);

  // Stable handlers so always-mounted memo'd tabs (JS Recon) don't re-render every tab switch.
  const createFinding = useCallback((d) => { setFindingDraft(d); setActiveTab('findings'); }, []);
  const sendToSubdomains = useCallback(async (hosts) => {
    const partials = (hosts || []).map((h) => ({ host: h, status: 'unknown', tech: [] }));
    const summary = await subs.importRecords(partials);
    showToast(`Sent ${summary.added} new host(s) to Subdomains`);
  }, [subs, showToast]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 1600);
    return () => clearTimeout(t);
  }, [toast]);

  // Global Ctrl/Cmd-K to open the command palette.
  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const confirmModal = (value) => {
    if (modal.mode === 'create') createProject(value);
    else if (modal.mode === 'rename') renameProject(modal.project.id, value);
    else if (modal.mode === 'delete') deleteProject(value);
    setModal(null);
  };

  const commands = useMemo(() => {
    const tabCmds = [
      { id: 'go-dashboard', icon: '▦', label: 'Go to Dashboard', group: 'navigate', run: () => setActiveTab('dashboard') },
      { id: 'go-scope', label: 'Go to Scope', group: 'navigate', run: () => setActiveTab('scope') },
      { id: 'go-subdomains', label: 'Go to Subdomains', group: 'navigate', run: () => setActiveTab('subdomains') },
      { id: 'go-ports', label: 'Go to Port Scan', group: 'navigate', run: () => setActiveTab('ports') },
      { id: 'go-urlparser', label: 'Go to URL Parser', group: 'navigate', run: () => setActiveTab('urlparser') },
      { id: 'go-jsrecon', label: 'Go to JS Recon', group: 'navigate', run: () => setActiveTab('jsrecon') },
      { id: 'go-surface', label: 'Go to Attack Surface', group: 'navigate', run: () => setActiveTab('surface') },
      { id: 'go-jwt', label: 'Go to JWT Decoder', group: 'navigate', run: () => setActiveTab('jwt') },
      { id: 'go-httpanalyzer', label: 'Go to HTTP Analyzer', group: 'navigate', run: () => setActiveTab('httpanalyzer') },
      { id: 'go-techstack', label: 'Go to Tech Stack', group: 'navigate', run: () => setActiveTab('techstack') },
      { id: 'go-findings', label: 'Go to Findings', group: 'navigate', run: () => setActiveTab('findings') },
      { id: 'go-notebook', label: 'Go to Notebook', group: 'navigate', run: () => setActiveTab('notebook') },
      { id: 'go-assets', label: 'Go to Assets', group: 'navigate', run: () => setActiveTab('assets') },
      { id: 'go-wordlists', label: 'Go to Wordlists', group: 'navigate', run: () => setActiveTab('wordlists') },
      { id: 'go-dorks', label: 'Go to GitHub Dorks', group: 'navigate', run: () => setActiveTab('dorks') },
    ];
    const actionCmds = [
      { id: 'import-project', icon: '+', label: 'Import project zip', group: 'action', run: () => setImportOpen(true) },
      { id: 'new-project', icon: '＋', label: 'Create new project', group: 'action', run: () => setModal({ mode: 'create' }) },
      { id: 'toggle-theme', icon: '◐', label: 'Toggle theme', group: 'action', run: toggleTheme },
    ];
    const projCmds = projects.map((p) => ({
      id: `switch-${p.id}`,
      icon: '●',
      label: `Switch to ${p.name}`,
      hint: `${(p.subdomainCount || 0).toLocaleString()} hosts`,
      group: 'project',
      run: () => switchProject(p.id),
    }));
    return [...tabCmds, ...actionCmds, ...projCmds];
  }, [projects, switchProject, toggleTheme]);

  const noProjects = !projectsLoading && projects.length === 0;

  return (
    <div className="app-shell">
      <TopBar
        projects={projects}
        activeId={activeId}
        activeProject={activeProject}
        onSwitch={switchProject}
        onNew={() => setModal({ mode: 'create' })}
        onRename={(p) => setModal({ mode: 'rename', project: p })}
        onDelete={(p) => setModal({ mode: 'delete', project: p })}
        onOpenPalette={() => setPaletteOpen(true)}
        theme={theme}
        onToggleTheme={toggleTheme}
        onImport={() => setImportOpen(true)}
      />

      <div className="layout">
        <Sidebar
          activeTab={activeTab}
          onTabChange={handleTabChange}
          hostCount={subs.records.length}
        />

        <main className="main">
          {projectsLoading ? (
            <div className="loading-state">Loading…</div>
          ) : noProjects ? (
            <div className="app-empty">
              <h2>No projects yet</h2>
              <p>
                Create a project per bug-bounty target to keep its recon data isolated. Start with
                the program root, e.g. <span className="mono">hackerone.com</span>.
              </p>
              <button className="btn btn-primary" onClick={() => setModal({ mode: 'create' })}>
                Create your first project
              </button>
            </div>
          ) : subs.isLoading ? (
            <div className="loading-state">Loading project data…</div>
          ) : (
            <ErrorBoundary resetKey={activeTab}>
              <Suspense fallback={<div className="loading-state">Loading…</div>}>
              {activeTab === 'dashboard' && (
                <Dashboard
                  activeProjectId={activeId}
                  records={subs.records}
                  activity={subs.activity}
                  projectName={activeProject?.name}
                  createdAt={activeProject?.createdAt}
                  theme={theme}
                  notes={notes}
                  onNotesChange={setNotes}
                  onViewNew={viewNew}
                  portRecords={ports.records}
                  scopeRules={scopeRules}
                  assets={assets}
                  onNavigate={setActiveTab}
                  portActivity={ports.activity}
                  assetActivity={assets.activity}
                />
              )}
              {activeTab === 'scope' && (
                <ScopeTab
                  rules={scopeRules}
                  onSaveRules={setScopeRules}
                  subRecords={subs.records}
                  portRecords={ports.records}
                  onCopyToast={showToast}
                />
              )}
              {activeTab === 'subdomains' && (
                <div className="tab-pane-fill">
                  <SubdomainTab
                    subs={subs}
                    onCopyToast={showToast}
                    keywords={keywords}
                    onSaveKeywords={setKeywords}
                    focusNewIds={focusNewIds}
                    onClearFocusNew={clearFocusNew}
                    scopeStatus={scopeStatus}
                    hasScope={scopeRules.length > 0}
                  />
                </div>
              )}
              {activeTab === 'ports' && (
                <PortTab
                  ports={ports}
                  projectName={activeProject?.name}
                  onCopyToast={showToast}
                  scopeStatus={scopeStatus}
                  hasScope={scopeRules.length > 0}
                  subRecords={subs.records}
                  onSendToSubdomains={async (hosts) => {
                    const partials = (hosts || []).map((h) => ({ host: h, status: 'unknown', tech: [] }));
                    const summary = await subs.importRecords(partials);
                    showToast(`Sent ${summary.added} new host(s) to Subdomains`);
                  }}
                />
              )}
              {activeTab === 'urlparser' && (
                <ReconUrlParser activeProjectId={activeId} active />
              )}
              {activeTab === 'jsrecon' && (
                <JsReconTab
                  activeProjectId={activeId}
                  onCreateFinding={createFinding}
                  onSendToSubdomains={sendToSubdomains}
                />
              )}
              {activeTab === 'surface' && (
                <SurfaceTab
                  activeProjectId={activeId}
                  subs={subs.records}
                  ports={ports.records}
                  scopeRules={scopeRules}
                />
              )}
              {activeTab === 'wordlists' && (
                <WordlistsTab techHints={[...new Set(subs.records.flatMap((r) => r.tech || []))]} />
              )}
              {activeTab === 'dorks' && <DorksTab defaultTarget={activeProject?.name || ''} />}
              {activeTab === 'jwt' && <JwtDecoderTab />}
              {activeTab === 'httpanalyzer' && <HttpAnalyzerTab />}
              {activeTab === 'techstack' && <TechStackTab records={subs.records} activeProjectId={activeId} />}
              {activeTab === 'findings' && (
                <FindingsTab
                  activeProjectId={activeId}
                  hosts={subs.records.map((r) => r.host)}
                  initialDraft={findingDraft}
                  onDraftConsumed={() => setFindingDraft(null)}
                />
              )}
              {activeTab === 'notebook' && (
                <NotebookTab
                  hosts={subs.records.map((r) => r.host)}
                  activeProjectId={activeId}
                  onCreateFinding={(d) => { setFindingDraft(d); setActiveTab('findings'); }}
                />
              )}
              {activeTab === 'assets' && (
                <AssetsTab
                  assets={assets}
                  onSave={setAssets}
                  onCopyToast={showToast}
                  subRecords={subs.records}
                  scopeStatus={scopeStatus}
                  hasScope={scopeRules.length > 0}
                  onSendToSubdomains={async (hosts) => {
                    const partials = (hosts || []).map((h) => ({ host: h, status: 'unknown', tech: [] }));
                    const summary = await subs.importRecords(partials);
                    showToast(`Sent ${summary.added} new host(s) to Subdomains`);
                  }}
                />
              )}
              {activeTab === 'settings' && (
                <SettingsTab
                  theme={theme}
                  onToggleTheme={toggleTheme}
                  projects={projects}
                  activeProject={activeProject}
                  onWipeProject={() => subs.clearAll()}
                />
              )}
            </Suspense>
            </ErrorBoundary>
          )}
        </main>
      </div>

      {modal && (
        <ProjectModal
          mode={modal.mode}
          project={modal.project}
          onConfirm={confirmModal}
          onClose={() => setModal(null)}
        />
      )}

      {paletteOpen && <CommandPalette commands={commands} onClose={() => setPaletteOpen(false)} />}

      {importOpen && (
        <Suspense fallback={null}>
          <ProjectImportModal
            activeProjectId={activeId}
            onNavigate={setActiveTab}
            onClose={() => setImportOpen(false)}
            onToast={showToast}
          />
        </Suspense>
      )}

      {toast && <div className="copy-toast">{toast}</div>}
    </div>
  );
}
