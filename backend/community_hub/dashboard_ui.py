"""
Factora — From Victim to Defender
Tactile Neumorphic Community Threat Intelligence Dashboard UI
Serves an interactive, responsive single-page web interface built strictly according to
the frontend design tokens in frontend/AGENTS.md.
"""

def get_community_dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FACTORA — From Victim to Defender | Community Cyber Defense</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- FontAwesome 6 Icons CDN -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        canvas: '#F2F4F7',
                        surface: '#FFFFFF',
                        surfaceSecondary: '#F8FAFC',
                        charcoal: '#141518',
                        charcoalHover: '#23252A',
                        borderMuted: '#E2E8F0',
                        borderSubtle: '#CBD5E1',
                        accentRed: '#EF4444',
                        accentAmber: '#F59E0B',
                        accentBlue: '#3B82F6',
                        accentGreen: '#10B981',
                        accentPurple: '#8B5CF6'
                    },
                    boxShadow: {
                        'tactile': '0 2px 0 0 rgba(0, 0, 0, 0.05), 0 4px 6px -1px rgba(0, 0, 0, 0.02)',
                        'tactile-pressed': 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.06)',
                        'tactile-card': '0 4px 20px -2px rgba(20, 21, 24, 0.04), 0 2px 6px -1px rgba(20, 21, 24, 0.02)'
                    }
                }
            }
        };
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
        body {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: #F2F4F7;
            color: #141518;
            -webkit-font-smoothing: antialiased;
        }
        pre, code, .font-mono {
            font-family: 'JetBrains Mono', monospace;
        }
        .badge-pill {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.2rem 0.65rem;
            border-radius: 9999px;
            font-size: 0.72rem;
            font-weight: 600;
            line-height: 1rem;
        }
        .skeleton {
            background: linear-gradient(90deg, #E2E8F0 25%, #F1F5F9 50%, #E2E8F0 75%);
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
        }
        @keyframes shimmer {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }
        .graph-node {
            cursor: pointer;
            transition: transform 0.2s, filter 0.2s;
        }
        .graph-node:hover {
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.15));
            transform: scale(1.05);
        }
    </style>
</head>
<body class="min-h-screen flex flex-col bg-canvas text-charcoal">

    <!-- Top Navigation Header -->
    <header class="bg-surface border-b border-borderMuted sticky top-0 z-40 shadow-tactile">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-9 h-9 rounded-2xl bg-charcoal text-white flex items-center justify-center font-extrabold text-sm shadow-tactile">
                    F
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <span class="font-extrabold text-sm tracking-tight text-charcoal">FACTORA</span>
                        <span class="text-[10px] font-bold uppercase tracking-wider bg-gray-100 text-charcoal px-2 py-0.5 rounded-full border border-borderMuted">FROM VICTIM TO DEFENDER</span>
                    </div>
                    <p class="text-[11px] text-gray-500 font-medium">Community Cyber Threat Intelligence & Mutual Defense</p>
                </div>
            </div>

            <!-- Navigation Links & Action Buttons -->
            <div class="flex items-center gap-2 sm:gap-3">
                <nav class="hidden lg:flex items-center gap-1 text-xs font-semibold text-gray-600 bg-canvas p-1 rounded-full border border-borderMuted">
                    <a href="#feedSection" class="px-3 py-1.5 rounded-full hover:bg-surface hover:text-charcoal transition-all">Threat Feed</a>
                    <a href="#threatAlertsSection" class="px-3 py-1.5 rounded-full hover:bg-surface hover:text-charcoal transition-all">Threat Alerts</a>
                    <a href="#educationSection" class="px-3 py-1.5 rounded-full hover:bg-surface hover:text-charcoal transition-all">Education</a>
                    <a href="#graphSection" class="px-3 py-1.5 rounded-full hover:bg-surface hover:text-charcoal transition-all">Relationship Graph</a>
                </nav>

                <button onclick="openModeratorModal()" title="Moderator Access" class="px-3 py-2 rounded-full bg-surface border border-borderMuted text-gray-700 hover:bg-gray-50 text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-all">
                    <i class="fa-solid fa-user-shield text-gray-500"></i>
                    <span class="hidden sm:inline">Moderator</span>
                </button>

                <button onclick="openMyReportsModal()" class="px-3 sm:px-4 py-2 rounded-full bg-surface border border-borderMuted text-charcoal hover:bg-gray-50 text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-all">
                    <i class="fa-solid fa-folder-open text-gray-500"></i>
                    <span class="hidden sm:inline">My Reports</span>
                    <span id="myReportsCountBadge" class="bg-gray-100 text-charcoal text-[10px] px-1.5 py-0.2 rounded-full font-bold">0</span>
                </button>

                <button onclick="openReportModal()" class="px-4 sm:px-5 py-2 rounded-full bg-charcoal hover:bg-charcoalHover text-white text-xs font-semibold flex items-center gap-1.5 shadow-tactile transition-all hover:scale-102">
                    <i class="fa-solid fa-plus text-[10px]"></i>
                    <span>Report Incident</span>
                </button>
            </div>
        </div>
    </header>

    <!-- Multi-Agent Decoupled Integration Status Bar -->
    <div class="bg-surface/80 border-b border-borderMuted px-6 py-2.5 backdrop-blur-sm">
        <div class="max-w-7xl mx-auto flex flex-wrap items-center justify-between text-xs gap-3">
            <div class="flex items-center gap-2 text-gray-500 font-medium">
                <i class="fa-solid fa-shield-halved text-gray-400"></i>
                <span class="font-semibold text-charcoal">Community Defense Network:</span>
                <span class="text-gray-400">Live SQLite Telemetry • Privacy Preserved</span>
            </div>
            <div class="flex items-center gap-3 flex-wrap">
                <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-50 text-accentGreen border border-emerald-200 text-[11px] font-semibold">
                    <span class="w-2 h-2 rounded-full bg-accentGreen animate-pulse"></span>
                    <span>Database: <strong>Active & Syncing</strong></span>
                </div>
                <div id="agent1StatusBadge" class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-gray-100 text-gray-600 border border-borderMuted text-[11px] font-semibold">
                    <span>Agent 1 (Threat Analyzer): <strong id="agent1StatusText" class="text-gray-500">HTTP Decoupled</strong></span>
                </div>
                <div id="agent2StatusBadge" class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-gray-100 text-gray-600 border border-borderMuted text-[11px] font-semibold">
                    <span>Agent 2 (Correlator): <strong id="agent2StatusText" class="text-gray-500">HTTP Decoupled</strong></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Error Banner (Hidden by default) -->
    <div id="errorBanner" class="hidden bg-red-50 border-b border-red-200 px-4 py-3 text-xs text-accentRed flex items-center justify-between">
        <div class="max-w-7xl mx-auto w-full flex items-center gap-2 font-medium">
            <i class="fa-solid fa-triangle-exclamation"></i>
            <span id="errorMessage">Unable to synchronize with community database.</span>
        </div>
        <button onclick="hideError()" class="text-gray-400 hover:text-gray-600"><i class="fa-solid fa-xmark"></i></button>
    </div>

    <!-- Main Container -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-12 flex-1">

        <!-- SECTION 1: DASHBOARD STATISTICS -->
        <section id="statisticsSection">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-sm font-bold uppercase tracking-wider text-gray-500 flex items-center gap-2">
                    <i class="fa-solid fa-chart-simple text-gray-400"></i> Ecosystem Defense Metrics
                </h2>
                <span class="text-xs text-gray-400 font-medium" id="statsLastUpdated">Live Database Sync</span>
            </div>

            <div id="statsGrid" class="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div class="h-28 rounded-3xl skeleton"></div>
                <div class="h-28 rounded-3xl skeleton"></div>
                <div class="h-28 rounded-3xl skeleton"></div>
                <div class="h-28 rounded-3xl skeleton"></div>
                <div class="h-28 rounded-3xl skeleton"></div>
            </div>
        </section>

        <!-- SECTION 2: COMMUNITY THREAT ALERTS (PROMPT 5 REQUIREMENT 1) -->
        <section id="threatAlertsSection">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
                <div>
                    <h2 class="text-sm font-bold uppercase tracking-wider text-accentRed flex items-center gap-2">
                        <i class="fa-solid fa-bullhorn"></i> Community Threat Alerts
                    </h2>
                    <p class="text-xs text-gray-500 mt-0.5">Potentially related cyber incidents identified from corroborated evidence and shared indicators</p>
                </div>
                <span class="text-[11px] font-semibold text-gray-400 bg-canvas px-3 py-1 rounded-full border border-borderMuted">
                    Caution: Shared indicators do not prove common attacker
                </span>
            </div>

            <div id="threatAlertsContainer" class="space-y-3">
                <div class="h-24 rounded-3xl skeleton"></div>
                <div class="h-24 rounded-3xl skeleton"></div>
            </div>
        </section>

        <!-- SECTION 3: COMMUNITY INCIDENT FEED & THREAT SEARCH (PART A & B) -->
        <section id="feedSection">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                <div>
                    <h2 class="text-sm font-bold uppercase tracking-wider text-charcoal flex items-center gap-2">
                        <i class="fa-solid fa-tower-broadcast"></i> Community Incident Feed & Threat Search
                    </h2>
                    <p class="text-xs text-gray-500 mt-0.5">Searchable multi-victim incident stream with backend pagination & indicator correlation</p>
                </div>
                <div class="flex items-center gap-2">
                    <span class="text-xs text-gray-400 font-medium" id="feedPaginationSummary">Live Database Feed</span>
                    <button onclick="resetAllFeedFilters()" title="Reset Filters" class="px-3 py-1.5 rounded-full bg-surface border border-borderMuted text-gray-600 hover:bg-gray-50 text-xs font-semibold shadow-sm transition-all flex items-center gap-1.5">
                        <i class="fa-solid fa-rotate-left text-[10px]"></i>
                        <span>Reset</span>
                    </button>
                </div>
            </div>

            <!-- Threat Search Bar -->
            <div class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted space-y-3 mb-5">
                <div class="flex flex-col sm:flex-row items-center gap-3">
                    <div class="relative w-full">
                        <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 text-xs"></i>
                        <input type="text" id="feedSearchInput" placeholder="Search Company, Domain, URL, Email, GitHub repo, Package, or Keyword..." 
                               onkeydown="if(event.key==='Enter') executeFeedSearch()"
                               class="w-full pl-9 pr-10 py-2.5 bg-canvas border border-borderMuted rounded-xl text-xs text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                        <button onclick="clearFeedSearch()" id="clearFeedSearchBtn" class="hidden absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 text-xs">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                    <button onclick="executeFeedSearch()" class="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-charcoal hover:bg-charcoalHover text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-tactile shrink-0 transition-all hover:scale-102">
                        <i class="fa-solid fa-bolt text-[10px]"></i>
                        <span>Threat Search</span>
                    </button>
                </div>

                <!-- Active Search Callout -->
                <div id="activeSearchSummaryBanner" class="hidden p-3 rounded-2xl bg-canvas border border-borderMuted text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div class="flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-accentBlue"></span>
                        <span class="text-gray-600" id="activeSearchQueryText">Active Query: <strong>-</strong></span>
                    </div>
                    <div class="flex items-center gap-3 text-[11px] font-semibold text-gray-500" id="activeSearchCountsText">
                        <span>Exact: 0</span>
                        <span>Correlated: 0</span>
                        <span>Approx: 0</span>
                    </div>
                </div>
            </div>

            <!-- Multi-Factor Feed Filters Bar -->
            <div class="bg-surface rounded-3xl p-4 shadow-tactile border border-borderMuted grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-5 text-xs">
                <div>
                    <label class="block text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1">Threat Category</label>
                    <select id="filterCategory" onchange="applyFeedFilters()" class="w-full px-3 py-2 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                        <option value="all">All Categories</option>
                        <option value="recruitment_fraud">Recruitment & Internships</option>
                        <option value="financial_scam">Financial Scams</option>
                        <option value="github_repo_risk">GitHub & Package Risks</option>
                        <option value="website_impersonation">Website Impersonation</option>
                        <option value="phishing">Phishing</option>
                        <option value="account_compromise">Account Compromise</option>
                    </select>
                </div>

                <div>
                    <label class="block text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1">Risk Level</label>
                    <select id="filterRiskLevel" onchange="applyFeedFilters()" class="w-full px-3 py-2 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                        <option value="all">All Risk Levels</option>
                        <option value="Critical Scam">Critical Scam</option>
                        <option value="High Risk">High Risk</option>
                        <option value="Caution">Caution</option>
                        <option value="Low Risk">Low Risk</option>
                        <option value="Verified Safe">Verified Safe</option>
                    </select>
                </div>

                <div>
                    <label class="block text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1">Verification Status</label>
                    <select id="filterStatus" onchange="applyFeedFilters()" class="w-full px-3 py-2 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                        <option value="all">All Statuses</option>
                        <option value="CORROBORATED">Corroborated (Verified)</option>
                        <option value="UNDER_REVIEW">Under Review</option>
                        <option value="SUBMITTED">Newly Submitted</option>
                        <option value="DISPUTED">Disputed</option>
                        <option value="CLOSED">Closed</option>
                    </select>
                </div>

                <div>
                    <label class="block text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1">Date Period</label>
                    <select id="filterDate" onchange="applyFeedFilters()" class="w-full px-3 py-2 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                        <option value="all">All Time</option>
                        <option value="today">Today (24h)</option>
                        <option value="past_7_days">Past 7 Days</option>
                        <option value="past_30_days">Past 30 Days</option>
                    </select>
                </div>

                <div class="col-span-2 sm:col-span-1">
                    <label class="block text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1">Incident Type</label>
                    <select id="filterIncidentType" onchange="applyFeedFilters()" class="w-full px-3 py-2 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                        <option value="all">All Types</option>
                    </select>
                </div>
            </div>

            <!-- Feed Stream Cards Container -->
            <div id="activityFeedContainer" class="space-y-4">
                <div class="h-28 rounded-3xl skeleton"></div>
                <div class="h-28 rounded-3xl skeleton"></div>
            </div>

            <!-- Empty State for Feed -->
            <div id="feedEmptyState" class="hidden bg-surface rounded-3xl p-10 text-center border border-borderMuted space-y-3">
                <div class="w-12 h-12 rounded-full bg-gray-100 text-gray-400 flex items-center justify-center text-xl mx-auto">
                    <i class="fa-solid fa-filter-circle-xmark"></i>
                </div>
                <div class="text-sm font-extrabold text-charcoal">No Incidents Found</div>
                <p class="text-xs text-gray-500 max-w-md mx-auto">No reports matched the specified filters or search term. Try resetting your filters to view all community reports.</p>
                <button onclick="resetAllFeedFilters()" class="mt-2 px-5 py-2 bg-charcoal text-white text-xs font-semibold rounded-full hover:bg-charcoalHover transition-all shadow-tactile">
                    Reset All Filters
                </button>
            </div>

            <!-- Pagination Controls -->
            <div class="mt-6 flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-borderMuted text-xs" id="feedPaginationControls">
                <div class="text-gray-500 font-medium" id="paginationRangeText">
                    Showing items 1 to 10
                </div>
                <div class="flex items-center gap-2">
                    <button onclick="changeFeedPage(-1)" id="prevPageBtn" class="px-4 py-2 rounded-full bg-surface border border-borderMuted text-charcoal hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed font-semibold shadow-sm transition-all flex items-center gap-1.5">
                        <i class="fa-solid fa-chevron-left text-[10px]"></i> Previous
                    </button>
                    <span id="currentPageIndicator" class="px-3.5 py-1.5 font-bold text-charcoal font-mono bg-canvas rounded-xl border border-borderMuted">Page 1</span>
                    <button onclick="changeFeedPage(1)" id="nextPageBtn" class="px-4 py-2 rounded-full bg-surface border border-borderMuted text-charcoal hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed font-semibold shadow-sm transition-all flex items-center gap-1.5">
                        Next <i class="fa-solid fa-chevron-right text-[10px]"></i>
                    </button>
                </div>
            </div>
        </section>

        <!-- SECTION 4: CYBER AWARENESS & EDUCATION CENTRE (PROMPT 5 REQUIREMENT 3) -->
        <section id="educationSection">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
                <div>
                    <h2 class="text-sm font-bold uppercase tracking-wider text-charcoal flex items-center gap-2">
                        <i class="fa-solid fa-graduation-cap text-accentBlue"></i> Cyber Awareness & Education Centre
                    </h2>
                    <p class="text-xs text-gray-500 mt-0.5">Practical, student-tailored security intelligence connected to live community fraud patterns</p>
                </div>
                <span class="text-xs text-gray-400 font-medium">6 Defensive Vectors</span>
            </div>

            <div id="educationGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                <div class="h-44 rounded-3xl skeleton"></div>
                <div class="h-44 rounded-3xl skeleton"></div>
                <div class="h-44 rounded-3xl skeleton"></div>
            </div>
        </section>

        <!-- SECTION 5: THREAT RELATIONSHIP GRAPH (PROMPT 5 REQUIREMENT 4) -->
        <section id="graphSection">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                <div>
                    <h2 class="text-sm font-bold uppercase tracking-wider text-charcoal flex items-center gap-2">
                        <i class="fa-solid fa-circle-nodes text-accentPurple"></i> Threat Relationship Graph
                    </h2>
                    <p class="text-xs text-gray-500 mt-0.5">Mathematically mapped connections between incidents, domains, repositories, and syndicates</p>
                </div>
                <div class="flex items-center gap-2">
                    <button onclick="loadGlobalGraph()" class="px-3.5 py-1.5 rounded-full bg-surface border border-borderMuted hover:bg-gray-50 text-xs font-semibold text-charcoal shadow-sm transition-all">
                        <i class="fa-solid fa-arrows-rotate text-[10px] mr-1"></i> Global Network
                    </button>
                </div>
            </div>

            <div class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted space-y-4">
                <!-- Graph Metadata & Legend Bar -->
                <div class="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-borderMuted text-xs">
                    <div class="flex items-center gap-3 flex-wrap text-[11px] font-semibold text-gray-600">
                        <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-charcoal"></span> Incident</span>
                        <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-accentBlue"></span> Domain</span>
                        <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-accentAmber"></span> Phone / UPI</span>
                        <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-accentPurple"></span> GitHub Repo</span>
                        <span class="flex items-center gap-1.5"><span class="w-3 h-3 rounded-full bg-accentGreen"></span> Campaign</span>
                    </div>
                    <div id="graphSummaryText" class="text-[11px] font-mono text-gray-400">
                        Loading network topology...
                    </div>
                </div>

                <!-- Graph Canvas / SVG Container -->
                <div id="graphCanvasContainer" class="relative w-full h-[460px] bg-canvas rounded-2xl border border-borderMuted overflow-hidden flex items-center justify-center">
                    <div class="text-center text-gray-400 text-xs space-y-2">
                        <i class="fa-solid fa-spinner fa-spin text-xl"></i>
                        <div>Rendering Threat Entity Graph...</div>
                    </div>
                </div>

                <!-- Cautionary Note on Graph Relationships -->
                <div class="bg-gray-50 border border-gray-200 rounded-2xl p-3 text-xs text-gray-500 flex items-start gap-2">
                    <i class="fa-solid fa-shield text-gray-400 mt-0.5"></i>
                    <span><strong>Graph Integrity Rule:</strong> Direct indicator edges (1.0 confidence) represent confirmed shared technical indicators (identical domain, phone, or repository). Similar company names alone are never treated as proof of connection.</span>
                </div>
            </div>
        </section>

    </main>

    <!-- Footer -->
    <footer class="bg-surface border-t border-borderMuted py-6 mt-12 text-center text-xs text-gray-500">
        <div class="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div class="flex items-center gap-2">
                <span class="font-extrabold text-charcoal">FACTORA — From Victim to Defender</span>
                <span>•</span>
                <span>Problem 1: Safety Tech — FAKE OR REAL</span>
            </div>
            <div class="flex items-center gap-4 text-gray-400 text-xs">
                <span>National Cyber Helpline: <strong>1930</strong></span>
                <span>•</span>
                <a href="https://cybercrime.gov.in" target="_blank" class="hover:text-charcoal underline">cybercrime.gov.in</a>
            </div>
        </div>
    </footer>

    <!-- ========================================== -->
    <!-- THREAT ALERT DETAILS DRAWER / MODAL        -->
    <!-- ========================================== -->
    <div id="threatAlertModal" class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-surface rounded-3xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl border border-borderMuted p-6 md:p-8 space-y-5">
            <div class="flex items-center justify-between border-b border-borderMuted pb-4">
                <div>
                    <span id="alertModalId" class="font-mono text-xs text-accentRed font-bold">ALT-ID</span>
                    <h3 id="alertModalTitle" class="text-base font-extrabold text-charcoal mt-0.5">Alert Title</h3>
                </div>
                <button onclick="closeThreatAlertModal()" class="w-8 h-8 rounded-full bg-gray-100 text-gray-500 hover:bg-gray-200 flex items-center justify-center transition-all">
                    <i class="fa-solid fa-xmark text-sm"></i>
                </button>
            </div>

            <div class="bg-red-50 border border-red-200 rounded-2xl p-4 text-xs space-y-2">
                <div class="font-bold text-accentRed flex items-center gap-2">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <span>Advisory Summary</span>
                </div>
                <p id="alertModalAdvisory" class="text-red-900 leading-relaxed"></p>
                <div class="text-[10px] text-red-700 bg-white/70 p-2 rounded-xl font-medium">
                    Disclaimer: Potentially Related Incidents. Shared indicators alone do not prove a common perpetrator or company compromise.
                </div>
            </div>

            <div>
                <h4 class="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Connected Incident Records</h4>
                <div id="alertModalIncidentsList" class="space-y-3">
                    <!-- Loaded dynamically -->
                </div>
            </div>

            <div class="pt-3 border-t border-borderMuted flex items-center justify-end">
                <button onclick="closeThreatAlertModal()" class="px-5 py-2 rounded-full bg-charcoal text-white hover:bg-charcoalHover text-xs font-semibold">
                    Close Advisory
                </button>
            </div>
        </div>
    </div>

    <!-- ========================================== -->
    <!-- EDUCATION TOPIC DETAIL MODAL               -->
    <!-- ========================================== -->
    <div id="educationModal" class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-surface rounded-3xl max-w-2xl w-full max-h-[92vh] overflow-y-auto shadow-2xl border border-borderMuted p-6 md:p-8 space-y-5">
            <div class="flex items-center justify-between border-b border-borderMuted pb-4">
                <div class="flex items-center gap-3">
                    <div id="eduModalIcon" class="w-10 h-10 rounded-2xl flex items-center justify-center text-sm shadow-sm"></div>
                    <div>
                        <span id="eduModalVector" class="text-[10px] font-bold uppercase tracking-wider text-gray-400">VECTOR</span>
                        <h3 id="eduModalTitle" class="text-base font-extrabold text-charcoal">Topic Title</h3>
                    </div>
                </div>
                <button onclick="closeEducationModal()" class="w-8 h-8 rounded-full bg-gray-100 text-gray-500 hover:bg-gray-200 flex items-center justify-center transition-all">
                    <i class="fa-solid fa-xmark text-sm"></i>
                </button>
            </div>

            <p id="eduModalSummary" class="text-xs text-gray-700 leading-relaxed bg-canvas p-4 rounded-2xl border border-borderMuted"></p>

            <!-- Warning Signs & Consequences -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div class="bg-canvas p-4 rounded-2xl border border-borderMuted space-y-2">
                    <h4 class="font-bold text-gray-800 flex items-center gap-1.5 text-accentAmber">
                        <i class="fa-solid fa-triangle-exclamation"></i> Common Warning Signs
                    </h4>
                    <ul id="eduModalSigns" class="space-y-1.5 text-gray-600 text-[11px] list-disc list-inside"></ul>
                </div>
                <div class="bg-canvas p-4 rounded-2xl border border-borderMuted space-y-2">
                    <h4 class="font-bold text-gray-800 flex items-center gap-1.5 text-accentRed">
                        <i class="fa-solid fa-skull-crossbones"></i> Potential Consequences
                    </h4>
                    <ul id="eduModalConsequences" class="space-y-1.5 text-gray-600 text-[11px] list-disc list-inside"></ul>
                </div>
            </div>

            <!-- Prevention Tips & Recommended Actions -->
            <div class="space-y-3 text-xs">
                <div class="bg-emerald-50 border border-emerald-200 p-4 rounded-2xl space-y-2">
                    <h4 class="font-bold text-emerald-900 flex items-center gap-1.5">
                        <i class="fa-solid fa-shield-check text-accentGreen"></i> Essential Prevention Tips
                    </h4>
                    <ul id="eduModalPrevention" class="space-y-1.5 text-emerald-800 text-[11px] list-disc list-inside"></ul>
                </div>

                <div class="bg-blue-50 border border-blue-200 p-4 rounded-2xl space-y-2">
                    <h4 class="font-bold text-blue-900 flex items-center gap-1.5">
                        <i class="fa-solid fa-phone-volume text-accentBlue"></i> If You Encounter This Threat
                    </h4>
                    <ul id="eduModalActions" class="space-y-1.5 text-blue-800 text-[11px] list-disc list-inside"></ul>
                </div>
            </div>

            <!-- Live SQLite Community Evidence Connection -->
            <div class="bg-canvas border border-borderMuted p-4 rounded-2xl text-xs space-y-2">
                <div class="flex items-center justify-between">
                    <h4 class="font-bold text-gray-800 flex items-center gap-1.5">
                        <i class="fa-solid fa-database text-gray-400"></i> Live Community Incident Evidence
                    </h4>
                    <span id="eduModalStatsBadge" class="badge-pill bg-gray-200 text-charcoal font-bold text-[10px]">0 Incidents</span>
                </div>
                <div id="eduModalSamples" class="space-y-2 pt-1"></div>
            </div>

            <div class="pt-3 border-t border-borderMuted flex items-center justify-end">
                <button onclick="closeEducationModal()" class="px-5 py-2 rounded-full bg-charcoal text-white hover:bg-charcoalHover text-xs font-semibold">
                    Done
                </button>
            </div>
        </div>
    </div>

    <!-- ========================================== -->
    <!-- MODERATOR PORTAL MODAL (PROMPT 5 REQUIREMENT 2) -->
    <!-- ========================================== -->
    <div id="moderatorModal" class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-surface rounded-3xl max-w-3xl w-full max-h-[92vh] overflow-y-auto shadow-2xl border border-borderMuted p-6 md:p-8 space-y-5">
            <div class="flex items-center justify-between border-b border-borderMuted pb-4">
                <div class="flex items-center gap-2.5">
                    <div class="w-9 h-9 rounded-2xl bg-charcoal text-white flex items-center justify-center text-sm">
                        <i class="fa-solid fa-user-shield"></i>
                    </div>
                    <div>
                        <h3 class="text-base font-extrabold text-charcoal">Community Incident Moderation Portal</h3>
                        <p class="text-xs text-gray-500 mt-0.5">Review submitted reports, verify evidence, flag duplicates/spam, and approve for public display</p>
                    </div>
                </div>
                <button onclick="closeModeratorModal()" class="w-8 h-8 rounded-full bg-gray-100 text-gray-500 hover:bg-gray-200 flex items-center justify-center transition-all">
                    <i class="fa-solid fa-xmark text-sm"></i>
                </button>
            </div>

            <!-- Moderator Key Input Gate -->
            <div id="modAuthGate" class="space-y-4">
                <div class="bg-canvas border border-borderMuted p-5 rounded-2xl space-y-3 text-xs">
                    <div class="font-bold text-charcoal flex items-center gap-1.5">
                        <i class="fa-solid fa-key text-accentAmber"></i> Backend Authorization Required
                    </div>
                    <p class="text-gray-600">Enter your secure moderator authorization key to access the review queue. Actions are strictly logged to an immutable audit trail.</p>
                    <div class="flex items-center gap-2">
                        <input type="password" id="modKeyInput" placeholder="Enter X-Moderator-Key..." 
                               value="factora-moderator-sentinel-2026"
                               class="flex-1 px-3.5 py-2.5 bg-surface border border-borderMuted rounded-xl font-mono text-xs focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                        <button onclick="authenticateModerator()" class="px-5 py-2.5 rounded-xl bg-charcoal text-white text-xs font-semibold hover:bg-charcoalHover shadow-tactile">
                            Unlock Queue
                        </button>
                    </div>
                    <span id="modAuthError" class="hidden text-[11px] text-accentRed font-semibold">Invalid moderator key. Access denied (HTTP 401).</span>
                </div>
            </div>

            <!-- Moderator Review Dashboard (Unlocked after valid key) -->
            <div id="modQueueContainer" class="hidden space-y-4">
                <div class="flex flex-wrap items-center justify-between gap-3 bg-canvas p-3 rounded-2xl border border-borderMuted text-xs">
                    <div class="flex items-center gap-2">
                        <span class="text-gray-500">Filter Status:</span>
                        <select id="modFilterStatus" onchange="loadModeratorQueue()" class="px-2.5 py-1 bg-surface border border-borderMuted rounded-lg font-semibold text-charcoal">
                            <option value="all">All Statuses</option>
                            <option value="SUBMITTED">SUBMITTED</option>
                            <option value="UNDER_REVIEW">UNDER_REVIEW</option>
                            <option value="CORROBORATED">CORROBORATED</option>
                            <option value="DISPUTED">DISPUTED</option>
                            <option value="CLOSED">CLOSED</option>
                            <option value="ARCHIVED">ARCHIVED</option>
                        </select>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="lockModeratorPortal()" class="text-xs text-gray-500 hover:text-charcoal underline">Lock Portal</button>
                    </div>
                </div>

                <div id="modIncidentCardsList" class="space-y-3 min-h-[200px]">
                    <!-- Dynamically populated -->
                </div>
            </div>
        </div>
    </div>

    <!-- ========================================== -->
    <!-- INCIDENT DETAIL MODAL                      -->
    <!-- ========================================== -->
    <div id="incidentModal" class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-surface rounded-3xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl border border-borderMuted p-6 md:p-8 space-y-5">
            <div class="flex items-center justify-between border-b border-borderMuted pb-4">
                <div>
                    <span id="modalRef" class="font-mono text-xs text-gray-400 font-bold">INCIDENT-ID</span>
                    <h3 id="modalTitle" class="text-base font-extrabold text-charcoal mt-0.5">Incident Title</h3>
                </div>
                <button onclick="closeIncidentModal()" class="w-8 h-8 rounded-full bg-gray-100 text-gray-500 hover:bg-gray-200 flex items-center justify-center transition-all">
                    <i class="fa-solid fa-xmark text-sm"></i>
                </button>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 bg-canvas p-4 rounded-2xl border border-borderMuted text-xs">
                <div>
                    <span class="text-gray-400 block text-[10px] font-bold uppercase">Category</span>
                    <span id="modalCategory" class="font-semibold text-charcoal">Recruitment Fraud</span>
                </div>
                <div>
                    <span class="text-gray-400 block text-[10px] font-bold uppercase">Status</span>
                    <span id="modalStatus" class="font-semibold text-charcoal">Corroborated</span>
                </div>
                <div>
                    <span class="text-gray-400 block text-[10px] font-bold uppercase">Reported Date</span>
                    <span id="modalDate" class="font-semibold text-charcoal">2026-10-31</span>
                </div>
                <div>
                    <span class="text-gray-400 block text-[10px] font-bold uppercase">Reported Loss</span>
                    <span id="modalLoss" class="font-semibold text-accentRed">Rs. 0</span>
                </div>
            </div>

            <div>
                <h4 class="text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Incident Description</h4>
                <p id="modalDescription" class="text-xs text-gray-700 leading-relaxed bg-canvas p-4 rounded-2xl border border-borderMuted font-normal"></p>
            </div>

            <div>
                <h4 class="text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Identified Suspect Indicators (Masked)</h4>
                <div id="modalIndicators" class="flex flex-wrap gap-2 text-xs"></div>
            </div>

            <!-- Agent 2 Correlation Status -->
            <div class="bg-canvas rounded-2xl p-4 border border-borderMuted space-y-2">
                <div class="flex items-center justify-between">
                    <span class="text-xs font-bold uppercase tracking-wider text-gray-500 flex items-center gap-1.5">
                        <i class="fa-solid fa-diagram-project text-gray-400"></i> Threat Syndicate Correlation
                    </span>
                    <span id="modalAgent2Badge" class="badge-pill bg-amber-50 text-amber-700 border border-amber-200 text-[10px]">
                        Pending Analysis (Agent 2 Offline)
                    </span>
                </div>
                <p id="modalAgent2Text" class="text-xs text-gray-600">
                    Cross-incident entity graph and campaign syndication link automatically once Agent 2 HTTP endpoint responds. No synthetic correlations generated.
                </p>
            </div>

            <div class="border-t border-borderMuted pt-4 space-y-3">
                <div class="flex flex-col sm:flex-row items-center justify-between gap-3">
                    <a href="https://cybercrime.gov.in" target="_blank" class="w-full sm:w-auto px-5 py-2.5 rounded-full bg-accentRed text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-tactile hover:bg-red-600 transition-all">
                        <i class="fa-solid fa-building-shield"></i> File on CyberCrime.gov.in
                    </a>
                    <button onclick="copyGeneratedFIRDraft()" id="copyFirBtn" class="w-full sm:w-auto px-5 py-2.5 rounded-full bg-charcoal text-white text-xs font-semibold flex items-center justify-center gap-2 shadow-tactile hover:bg-charcoalHover transition-all">
                        <i class="fa-regular fa-copy"></i> Copy Pre-Filled FIR Draft
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- ========================================== -->
    <!-- REPORT AN INCIDENT MODAL (11 FIELDS)       -->
    <!-- ========================================== -->
    <div id="reportModal" class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-surface rounded-3xl max-w-2xl w-full max-h-[92vh] overflow-y-auto shadow-2xl border border-borderMuted p-6 md:p-8 space-y-5">
            <div class="flex items-center justify-between border-b border-borderMuted pb-4">
                <div>
                    <h3 class="text-base font-extrabold text-charcoal flex items-center gap-2">
                        <i class="fa-solid fa-shield-virus text-charcoal"></i> Report a Suspicious Cyber Incident
                    </h3>
                    <p class="text-xs text-gray-500 mt-0.5">Submit deceptive campus offers, phishing attempts, tasks, or malicious repos.</p>
                </div>
                <button onclick="closeReportModal()" class="w-8 h-8 rounded-full bg-gray-100 text-gray-500 hover:bg-gray-200 flex items-center justify-center transition-all">
                    <i class="fa-solid fa-xmark text-sm"></i>
                </button>
            </div>

            <div class="bg-emerald-50 border border-emerald-200 rounded-2xl p-3.5 flex items-center justify-between text-xs">
                <div class="flex items-center gap-2.5">
                    <div class="w-7 h-7 rounded-full bg-emerald-100 flex items-center justify-center text-accentGreen text-xs">
                        <i class="fa-solid fa-user-secret"></i>
                    </div>
                    <div>
                        <span class="text-gray-600">Reporting Pseudonym:</span>
                        <span id="formPseudonymBadge" class="font-mono text-emerald-900 font-bold ml-1">student-guardian-anon</span>
                    </div>
                </div>
                <span class="text-[10px] text-emerald-700 bg-white/90 px-2.5 py-0.5 rounded-full border border-emerald-300 font-medium">Privacy Preserved</span>
            </div>

            <form id="scamReportForm" onsubmit="handleScamReportSubmit(event)" class="space-y-4 text-xs">
                <div>
                    <label class="block font-bold text-gray-800 mb-1">1. Incident Title *</label>
                    <input type="text" id="formTitle" required minlength="5" placeholder="e.g. TCS Laptop Security Deposit WhatsApp Offer" 
                           class="w-full px-3.5 py-2.5 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block font-bold text-gray-800 mb-1">2. Threat Category *</label>
                        <select id="formCategory" required class="w-full px-3.5 py-2.5 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                            <option value="recruitment_fraud">Recruitment & Internship Fraud</option>
                            <option value="financial_scam">Financial Scams</option>
                            <option value="github_repo_risk">GitHub Repository & Package Risks</option>
                            <option value="website_impersonation">Website Impersonation</option>
                            <option value="phishing">Phishing</option>
                            <option value="account_compromise">Account Compromise</option>
                        </select>
                    </div>
                    <div>
                        <label class="block font-bold text-gray-800 mb-1">4. Claimed Company / Organization (Optional)</label>
                        <input type="text" id="formOrg" placeholder="e.g. Tata Consultancy Services (alleged)" 
                               class="w-full px-3.5 py-2.5 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                    </div>
                </div>

                <div>
                    <label class="block font-bold text-gray-800 mb-1">3. Description of What Happened *</label>
                    <textarea id="formDescription" required minlength="10" rows="3" placeholder="Explain how you were approached, what was promised, what documents were sent, and what actions were requested..." 
                              class="w-full px-3.5 py-2.5 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20 leading-relaxed"></textarea>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block font-bold text-gray-800 mb-1">5. Suspicious Email, Domain or URL (Optional)</label>
                        <input type="text" id="formSuspiciousLink" placeholder="e.g. hr@tcs-careers-portal.in, bit.ly/internship-2026" 
                               class="w-full px-3.5 py-2.5 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                    </div>
                    <div>
                        <label class="block font-bold text-gray-800 mb-1">6. GitHub Repository Link (Optional)</label>
                        <input type="text" id="formGithubRepo" placeholder="e.g. https://github.com/recruiter-tests/assessment-task" 
                               class="w-full px-3.5 py-2.5 bg-canvas border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                    </div>
                </div>

                <!-- Financial Loss -->
                <div class="bg-canvas p-3.5 rounded-2xl border border-borderMuted space-y-3">
                    <div class="flex items-center justify-between">
                        <label class="font-bold text-gray-800">7. Did Financial Loss Occur?</label>
                        <div class="flex items-center gap-3">
                            <label class="flex items-center gap-1.5 cursor-pointer">
                                <input type="radio" name="lossOccurred" value="no" checked onchange="toggleLossAmount(false)" class="text-charcoal">
                                <span class="text-gray-700">No Loss</span>
                            </label>
                            <label class="flex items-center gap-1.5 cursor-pointer">
                                <input type="radio" name="lossOccurred" value="yes" onchange="toggleLossAmount(true)" class="text-charcoal">
                                <span class="text-gray-700 font-semibold text-accentRed">Yes, Money Lost</span>
                            </label>
                        </div>
                    </div>

                    <div id="lossAmountContainer" class="hidden pt-2 border-t border-borderMuted">
                        <label class="block font-bold text-gray-800 mb-1">8. Approximate Amount Lost (INR) *</label>
                        <div class="relative">
                            <span class="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 font-bold">Rs.</span>
                            <input type="number" step="50" min="0" id="formAmount" placeholder="3500.00" 
                                   class="w-full pl-11 pr-3.5 py-2 bg-surface border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                        </div>
                    </div>
                </div>

                <!-- Complaint Status -->
                <div class="bg-canvas p-3.5 rounded-2xl border border-borderMuted space-y-3">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div>
                            <label class="font-bold text-gray-800">9. Was an Official Cybercrime Complaint Filed?</label>
                            <span class="text-[10px] text-gray-400 block">Optional — not required to submit a community report</span>
                        </div>
                        <div class="flex items-center gap-3 shrink-0">
                            <label class="flex items-center gap-1.5 cursor-pointer">
                                <input type="radio" name="complaintFiled" value="no" checked onchange="toggleComplaintAck(false)" class="text-charcoal">
                                <span class="text-gray-700">No</span>
                            </label>
                            <label class="flex items-center gap-1.5 cursor-pointer">
                                <input type="radio" name="complaintFiled" value="yes" onchange="toggleComplaintAck(true)" class="text-charcoal">
                                <span class="text-gray-700 font-semibold text-accentBlue">Yes, Filed</span>
                            </label>
                        </div>
                    </div>

                    <div id="complaintAckContainer" class="hidden pt-2 border-t border-borderMuted">
                        <label class="block font-bold text-gray-800 mb-1">10. Complaint Acknowledgement Reference (Optional)</label>
                        <input type="text" id="formAckRef" placeholder="e.g. 2026/CYBER/904128" 
                               class="w-full px-3.5 py-2 bg-surface border border-borderMuted rounded-xl text-charcoal focus:outline-none focus:ring-2 focus:ring-charcoal/20">
                    </div>
                </div>

                <!-- Evidence Upload -->
                <div>
                    <label class="block font-bold text-gray-800 mb-1">11. Supporting Screenshots or Documents (Optional)</label>
                    <div class="border-2 border-dashed border-borderMuted hover:border-gray-400 rounded-2xl p-4 text-center cursor-pointer bg-canvas transition-all" onclick="document.getElementById('formEvidenceFiles').click()">
                        <i class="fa-solid fa-cloud-arrow-up text-xl text-gray-400 mb-1"></i>
                        <div class="text-xs font-semibold text-charcoal">Upload screenshots, offer letters, or transaction proof</div>
                        <div class="text-[10px] text-gray-400 mt-0.5">PNG, JPG, WEBP, PDF, TXT (up to 10 MB each)</div>
                        <input type="file" id="formEvidenceFiles" multiple accept=".png,.jpg,.jpeg,.webp,.pdf,.txt" class="hidden" onchange="handleEvidenceFilesChange(event)">
                    </div>
                    <div id="selectedFilesChips" class="flex flex-wrap gap-2 mt-2"></div>
                </div>

                <div class="pt-3 flex items-center justify-end gap-3 border-t border-borderMuted">
                    <button type="button" onclick="closeReportModal()" class="px-5 py-2.5 rounded-full border border-borderMuted text-gray-600 hover:bg-gray-50 font-semibold">Cancel</button>
                    <button type="submit" id="submitReportBtn" class="px-6 py-2.5 rounded-full bg-charcoal text-white hover:bg-charcoalHover font-semibold flex items-center gap-2 shadow-tactile transition-all">
                        <span>Submit Incident Report</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- SUCCESS CONFIRMATION MODAL -->
    <div id="successModal" class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-surface rounded-3xl max-w-md w-full shadow-2xl border border-borderMuted p-6 md:p-8 space-y-5 text-center">
            <div class="w-16 h-16 rounded-full bg-emerald-50 text-accentGreen flex items-center justify-center text-3xl mx-auto shadow-sm border border-emerald-200">
                <i class="fa-solid fa-circle-check"></i>
            </div>
            <div>
                <h3 class="text-lg font-extrabold text-charcoal">Incident Successfully Submitted!</h3>
                <p class="text-xs text-gray-500 mt-1">Your report has been securely registered in the Factora community defense network.</p>
            </div>
            <div class="bg-canvas border border-borderMuted rounded-2xl p-4 space-y-2 text-left">
                <div class="flex items-center justify-between">
                    <div>
                        <div class="text-[10px] uppercase font-bold text-gray-400">Assigned Incident ID</div>
                        <div id="confirmedIncidentId" class="font-mono text-sm font-extrabold text-charcoal">COMM-2026-XXXX</div>
                    </div>
                    <button onclick="copyConfirmedIncidentId()" class="p-2 rounded-xl bg-surface border border-borderMuted hover:bg-gray-100 text-xs">
                        <i class="fa-regular fa-copy text-gray-500"></i>
                    </button>
                </div>
                <div class="flex items-center justify-between pt-2 border-t border-borderMuted text-xs">
                    <span class="text-gray-500">Initial Status:</span>
                    <span class="badge-pill bg-amber-50 text-amber-800 border border-amber-200 text-[10px] font-bold">
                        SUBMITTED (Under Review)
                    </span>
                </div>
            </div>
            <div id="goldenHourNotice" class="hidden bg-red-50 border border-red-200 rounded-2xl p-3 text-left text-xs text-red-900 space-y-1">
                <div class="font-bold flex items-center gap-1.5 text-accentRed">
                    <i class="fa-solid fa-triangle-exclamation"></i> Immediate Golden Hour Action
                </div>
                <p class="text-[11px] text-red-800">Call national helpline <strong>1930</strong> immediately to initiate CFCFRMS banking freeze on scammer's receiving account.</p>
            </div>
            <div class="space-y-2.5 pt-2">
                <button onclick="closeSuccessAndOpenMyReports()" class="w-full py-2.5 rounded-2xl bg-surface border border-borderMuted hover:bg-gray-50 text-xs font-semibold text-charcoal transition-all">
                    View in My Reports
                </button>
                <button onclick="closeSuccessModal()" class="w-full text-xs text-gray-400 hover:text-gray-600 font-medium">
                    Done
                </button>
            </div>
        </div>
    </div>

    <!-- MY REPORTS MODAL -->
    <div id="myReportsModal" class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm hidden flex items-center justify-center p-4">
        <div class="bg-surface rounded-3xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl border border-borderMuted p-6 md:p-8 space-y-5">
            <div class="flex items-center justify-between border-b border-borderMuted pb-4">
                <div>
                    <h3 class="text-base font-extrabold text-charcoal flex items-center gap-2">
                        <i class="fa-solid fa-folder-open text-charcoal"></i> My Submitted Incidents
                    </h3>
                    <p class="text-xs text-gray-500 mt-0.5">Track your community reports and check their real-time verification review status.</p>
                </div>
                <button onclick="closeMyReportsModal()" class="w-8 h-8 rounded-full bg-gray-100 text-gray-500 hover:bg-gray-200 flex items-center justify-center transition-all">
                    <i class="fa-solid fa-xmark text-sm"></i>
                </button>
            </div>
            <div id="myReportsListContainer" class="space-y-3 min-h-[160px]"></div>
            <div class="pt-3 border-t border-borderMuted flex items-center justify-between">
                <button onclick="openReportModalFromMyReports()" class="px-4 py-2 rounded-full bg-charcoal text-white hover:bg-charcoalHover text-xs font-semibold flex items-center gap-1.5 shadow-sm">
                    <i class="fa-solid fa-plus text-[10px]"></i> Submit New Incident
                </button>
                <button onclick="closeMyReportsModal()" class="px-4 py-2 rounded-full border border-borderMuted text-gray-600 hover:bg-gray-50 text-xs font-semibold">
                    Close
                </button>
            </div>
        </div>
    </div>

    <!-- ========================================== -->
    <!-- JAVASCRIPT APPLICATION LOGIC               -->
    <!-- ========================================== -->
    <script>
        let currentModalIncident = null;
        let activeModeratorKey = sessionStorage.getItem('factora_moderator_key') || null;

        // Feed State
        let feedState = {
            page: 1,
            pageSize: 10,
            totalPages: 1,
            totalItems: 0,
            isSearchMode: false,
            currentQuery: ''
        };

        let selectedEvidenceFiles = [];
        let latestSubmittedIncident = null;

        function getUserPseudonym() {
            let p = localStorage.getItem('factora_user_pseudonym');
            if (!p) {
                const prefixes = ["student", "campus", "scholar", "coder", "peer", "cyber"];
                const roles = ["guardian", "sentinel", "defender", "watcher", "scout", "ranger"];
                const randHex = Math.random().toString(16).substring(2, 6);
                p = `${prefixes[Math.floor(Math.random() * prefixes.length)]}-${roles[Math.floor(Math.random() * roles.length)]}-${randHex}`;
                localStorage.setItem('factora_user_pseudonym', p);
            }
            return p;
        }

        async function updateMyReportsCount() {
            const pseudonym = getUserPseudonym();
            try {
                const res = await fetch(`/api/community/reports/my-submissions?pseudonym=${encodeURIComponent(pseudonym)}`);
                if (res.ok) {
                    const data = await res.json();
                    const badge = document.getElementById('myReportsCountBadge');
                    if (badge) badge.innerText = data.submissions_count || 0;
                }
            } catch (e) {
                console.error("Failed to load user submissions count", e);
            }
        }

        // Toggle helpers
        function toggleLossAmount(hasLoss) {
            const container = document.getElementById('lossAmountContainer');
            const input = document.getElementById('formAmount');
            if (hasLoss) {
                container.classList.remove('hidden');
                input.required = true;
            } else {
                container.classList.add('hidden');
                input.required = false;
                input.value = '';
            }
        }

        function toggleComplaintAck(isFiled) {
            const container = document.getElementById('complaintAckContainer');
            if (isFiled) {
                container.classList.remove('hidden');
            } else {
                container.classList.add('hidden');
                document.getElementById('formAckRef').value = '';
            }
        }

        function handleEvidenceFilesChange(e) {
            const files = Array.from(e.target.files);
            selectedEvidenceFiles = files;
            const chips = document.getElementById('selectedFilesChips');
            chips.innerHTML = files.map((f, i) => `
                <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-gray-100 text-charcoal text-[11px] font-medium border border-borderMuted">
                    <i class="fa-solid fa-paperclip text-[10px] text-gray-500"></i>
                    <span class="truncate max-w-[150px]">${f.name}</span>
                    <span class="text-[9px] text-gray-400">(${(f.size / 1024).toFixed(0)} KB)</span>
                </span>
            `).join('');
        }

        function openReportModal() {
            document.getElementById('formPseudonymBadge').innerText = getUserPseudonym();
            document.getElementById('reportModal').classList.remove('hidden');
        }

        function closeReportModal() {
            document.getElementById('reportModal').classList.add('hidden');
            document.getElementById('scamReportForm').reset();
            selectedEvidenceFiles = [];
            document.getElementById('selectedFilesChips').innerHTML = '';
            toggleLossAmount(false);
            toggleComplaintAck(false);
        }

        async function handleScamReportSubmit(e) {
            e.preventDefault();
            const btn = document.getElementById('submitReportBtn');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Submitting...`;

            try {
                let uploadedFilenames = [];
                if (selectedEvidenceFiles.length > 0) {
                    const formData = new FormData();
                    for (const f of selectedEvidenceFiles) {
                        formData.append('files', f);
                    }
                    const uploadRes = await fetch('/api/community/upload-evidence', {
                        method: 'POST',
                        body: formData
                    });
                    if (uploadRes.ok) {
                        const upData = await uploadRes.json();
                        uploadedFilenames = upData.filenames || [];
                    }
                }

                const lossOccurred = document.querySelector('input[name="lossOccurred"]:checked').value === 'yes';
                const complaintFiled = document.querySelector('input[name="complaintFiled"]:checked').value === 'yes';
                const userPseudonym = getUserPseudonym();

                const payload = {
                    incident_title: document.getElementById('formTitle').value.trim(),
                    scam_type: document.getElementById('formCategory').value,
                    description: document.getElementById('formDescription').value.trim(),
                    claimed_organization: document.getElementById('formOrg').value.trim() || "Unspecified Entity",
                    suspicious_url_or_domain: document.getElementById('formSuspiciousLink').value.trim() || null,
                    github_repo_link: document.getElementById('formGithubRepo').value.trim() || null,
                    financial_loss_occurred: lossOccurred,
                    amount_demanded_or_lost_inr: lossOccurred ? (parseFloat(document.getElementById('formAmount').value) || 0.0) : 0.0,
                    official_complaint_filed: complaintFiled,
                    complaint_ack_ref: complaintFiled ? (document.getElementById('formAckRef').value.trim() || null) : null,
                    evidence_filenames: uploadedFilenames,
                    user_pseudonym: userPseudonym,
                    scammer_contacts: [],
                    scammer_links: []
                };

                const res = await fetch('/api/community/report', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-User-Pseudonym': userPseudonym
                    },
                    body: JSON.stringify(payload)
                });

                if (!res.ok) {
                    const errData = await res.json();
                    throw new Error(errData.detail || 'Submission failed');
                }

                const result = await res.json();
                latestSubmittedIncident = result;

                closeReportModal();
                showSuccessConfirmation(result, lossOccurred);
                updateMyReportsCount();
                refreshDashboard();
            } catch (err) {
                alert(`Error submitting report: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<span>Submit Incident Report</span>`;
            }
        }

        function showSuccessConfirmation(result, lossOccurred) {
            document.getElementById('confirmedIncidentId').innerText = result.incident_id;
            const goldenHourNotice = document.getElementById('goldenHourNotice');
            if (lossOccurred) {
                goldenHourNotice.classList.remove('hidden');
            } else {
                goldenHourNotice.classList.add('hidden');
            }
            document.getElementById('successModal').classList.remove('hidden');
        }

        function closeSuccessModal() {
            document.getElementById('successModal').classList.add('hidden');
        }

        function copyConfirmedIncidentId() {
            const id = document.getElementById('confirmedIncidentId').innerText;
            navigator.clipboard.writeText(id).then(() => {
                alert(`Incident ID ${id} copied!`);
            });
        }

        function closeSuccessAndOpenMyReports() {
            closeSuccessModal();
            openMyReportsModal();
        }

        async function openMyReportsModal() {
            const pseudonym = getUserPseudonym();
            document.getElementById('myReportsModal').classList.remove('hidden');
            const container = document.getElementById('myReportsListContainer');
            container.innerHTML = `<div class="h-24 rounded-2xl skeleton"></div>`;

            try {
                const res = await fetch(`/api/community/reports/my-submissions?pseudonym=${encodeURIComponent(pseudonym)}`);
                if (!res.ok) throw new Error("Failed to load submissions");
                const data = await res.json();
                renderMyReportsList(data.submissions || []);
            } catch (e) {
                container.innerHTML = `<div class="text-center py-8 text-gray-400 text-xs">Could not load reports.</div>`;
            }
        }

        function renderMyReportsList(submissions) {
            const container = document.getElementById('myReportsListContainer');
            if (!submissions || submissions.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-10 bg-canvas rounded-2xl border border-borderMuted space-y-2">
                        <div class="text-xs font-bold text-charcoal">No Submitted Reports Yet</div>
                        <p class="text-[11px] text-gray-500 max-w-xs mx-auto">Incidents you report using this browser session will appear here with verification tracking.</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = submissions.map(sub => `
                <div class="bg-canvas border border-borderMuted rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                    <div class="space-y-1">
                        <div class="flex items-center gap-2">
                            <span class="font-mono text-[11px] font-extrabold text-charcoal">${sub.incident_ref}</span>
                            <span class="badge-pill bg-amber-50 text-amber-800 border border-amber-200 text-[10px] font-bold">
                                ${sub.verification_status}
                            </span>
                        </div>
                        <div class="font-bold text-gray-900 text-xs">${sub.incident_title}</div>
                        <div class="text-[11px] text-gray-500">
                            Loss: <strong>Rs. ${sub.amount_demanded_or_lost_inr.toLocaleString()}</strong>
                        </div>
                    </div>
                    <button onclick="inspectSubmittedIncident('${sub.incident_ref}')" class="px-3 py-1.5 rounded-full bg-surface border border-borderMuted hover:bg-gray-50 text-[11px] font-semibold text-charcoal shadow-sm">
                        Inspect
                    </button>
                </div>
            `).join('');
        }

        function closeMyReportsModal() {
            document.getElementById('myReportsModal').classList.add('hidden');
        }

        function openReportModalFromMyReports() {
            closeMyReportsModal();
            openReportModal();
        }

        function inspectSubmittedIncident(ref) {
            closeMyReportsModal();
            openIncidentModal(ref);
        }

        // ==========================================
        // 1. DASHBOARD TELEMETRY & STATS
        // ==========================================
        async function refreshDashboard() {
            try {
                const res = await fetch('/api/community/dashboard');
                if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
                const data = await res.json();

                renderStatistics(data.statistics);
                document.getElementById('statsLastUpdated').innerText = `Synced at ${new Date().toLocaleTimeString()}`;
                hideError();
            } catch (err) {
                console.error("Dashboard refresh error:", err);
                showError("Unable to load live telemetry from community database.");
            }
        }

        function renderStatistics(stats) {
            const grid = document.getElementById('statsGrid');
            grid.innerHTML = `
                <div class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted flex flex-col justify-between">
                    <span class="text-[11px] font-bold uppercase tracking-wider text-gray-400">Total Incidents</span>
                    <div class="mt-4 text-2xl font-extrabold text-charcoal tracking-tight">${stats.total_submitted_incidents}</div>
                </div>
                <div class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted flex flex-col justify-between">
                    <span class="text-[11px] font-bold uppercase tracking-wider text-gray-400">Newly Reported</span>
                    <div class="mt-4 text-2xl font-extrabold text-accentAmber tracking-tight">${stats.newly_reported_incidents}</div>
                </div>
                <div class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted flex flex-col justify-between">
                    <span class="text-[11px] font-bold uppercase tracking-wider text-gray-400">Corroborated</span>
                    <div class="mt-4 text-2xl font-extrabold text-accentGreen tracking-tight">${stats.corroborated_reports}</div>
                </div>
                <div class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted flex flex-col justify-between">
                    <span class="text-[11px] font-bold uppercase tracking-wider text-gray-400">Syndicates</span>
                    <div class="mt-4 text-2xl font-extrabold text-accentPurple tracking-tight">${stats.potential_threat_campaigns}</div>
                </div>
                <div class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted flex flex-col justify-between">
                    <span class="text-[11px] font-bold uppercase tracking-wider text-gray-400">Active Alerts</span>
                    <div class="mt-4 text-2xl font-extrabold text-accentRed tracking-tight">${stats.active_community_alerts}</div>
                </div>
            `;
        }

        // ==========================================
        // 2. DYNAMIC COMMUNITY THREAT ALERTS (PROMPT 5 REQ 1)
        // ==========================================
        async function loadThreatAlerts() {
            const container = document.getElementById('threatAlertsContainer');
            try {
                const res = await fetch('/api/community/alerts');
                if (!res.ok) throw new Error("Could not load alerts");
                const data = await res.json();
                const alerts = data.alerts || [];

                if (alerts.length === 0) {
                    container.innerHTML = `
                        <div class="bg-surface rounded-3xl p-6 text-center text-xs text-gray-500 border border-borderMuted">
                            No active multi-incident threat alerts detected in the database.
                        </div>
                    `;
                    return;
                }

                container.innerHTML = alerts.map(a => `
                    <div class="bg-surface rounded-3xl p-5 shadow-tactile border-l-4 border-l-accentRed border-borderMuted flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-gray-400 transition-all">
                        <div class="space-y-1.5 flex-1">
                            <div class="flex items-center gap-2 flex-wrap">
                                <span class="badge-pill bg-red-50 text-accentRed border border-red-200">
                                    <i class="fa-solid fa-triangle-exclamation"></i> ${a.severity}
                                </span>
                                <span class="badge-pill bg-gray-100 text-charcoal border border-borderMuted text-[10px]">
                                    ${a.category}
                                </span>
                                <span class="text-[11px] text-gray-400 font-medium">
                                    <i class="fa-regular fa-calendar"></i> ${a.date}
                                </span>
                            </div>
                            <h3 class="text-xs font-bold text-charcoal">${a.title}</h3>
                            <p class="text-xs text-gray-600 leading-relaxed">${a.advisory_text}</p>
                            <div class="flex items-center gap-3 pt-1 text-[11px] text-gray-400 flex-wrap">
                                <span>Related Incidents: <strong class="text-charcoal">${a.number_of_related_incidents} reports</strong></span>
                                <span>•</span>
                                <span>Confidence: <strong class="text-charcoal">${(a.relationship_confidence * 100).toFixed(0)}%</strong></span>
                                <span>•</span>
                                <span>Status: <strong class="text-accentGreen">${a.status}</strong></span>
                            </div>
                        </div>
                        <div class="shrink-0 self-end md:self-center">
                            <button onclick="inspectThreatAlert('${a.alert_id}')" class="px-4 py-2 rounded-full bg-charcoal hover:bg-charcoalHover text-white text-xs font-semibold flex items-center gap-1.5 shadow-tactile transition-all">
                                <span>View Connected Incidents</span>
                                <i class="fa-solid fa-arrow-right text-[10px]"></i>
                            </button>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                console.error("Alerts error:", e);
                container.innerHTML = `<div class="text-xs text-gray-500 p-4">Unable to load threat alerts.</div>`;
            }
        }

        async function inspectThreatAlert(alertId) {
            try {
                const res = await fetch(`/api/community/alerts/${alertId}`);
                if (!res.ok) throw new Error("Failed to load alert details");
                const data = await res.json();
                const a = data.alert;

                document.getElementById('alertModalId').innerText = a.alert_id;
                document.getElementById('alertModalTitle').innerText = a.title;
                document.getElementById('alertModalAdvisory').innerText = a.advisory_text;

                const listContainer = document.getElementById('alertModalIncidentsList');
                const rel = a.related_incidents || [];
                if (rel.length === 0) {
                    listContainer.innerHTML = '<div class="text-xs text-gray-400 italic">No detailed incident records found.</div>';
                } else {
                    listContainer.innerHTML = rel.map(inc => `
                        <div class="bg-canvas p-3.5 rounded-2xl border border-borderMuted flex items-center justify-between gap-3 text-xs">
                            <div class="space-y-1">
                                <div class="flex items-center gap-2">
                                    <span class="font-mono font-bold text-charcoal">${inc.incident_ref}</span>
                                    <span class="badge-pill font-bold text-[10px]" style="background-color: ${inc.risk_color}15; color: ${inc.risk_color};">
                                        ${inc.risk_level}
                                    </span>
                                </div>
                                <div class="font-semibold text-gray-800">${inc.incident_title}</div>
                                <div class="text-[11px] text-gray-400">${inc.reported_at} • Loss: Rs. ${inc.amount_demanded_or_lost_inr.toLocaleString()}</div>
                            </div>
                            <button onclick="closeThreatAlertModal(); openIncidentModal('${inc.incident_ref}')" class="px-3 py-1.5 rounded-full bg-surface border border-borderMuted hover:bg-gray-50 font-semibold text-[11px] shadow-sm">
                                Inspect
                            </button>
                        </div>
                    `).join('');
                }

                document.getElementById('threatAlertModal').classList.remove('hidden');
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        function closeThreatAlertModal() {
            document.getElementById('threatAlertModal').classList.add('hidden');
        }

        // ==========================================
        // 3. CYBER AWARENESS & EDUCATION (PROMPT 5 REQ 3)
        // ==========================================
        async function loadEducationCentre() {
            const grid = document.getElementById('educationGrid');
            try {
                const res = await fetch('/api/community/education');
                if (!res.ok) throw new Error("Could not load education modules");
                const data = await res.json();
                const topics = data.topics || [];

                grid.innerHTML = topics.map(t => `
                    <div onclick="openEducationTopic('${t.topic_id}')" class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted hover:border-gray-400 cursor-pointer transition-all hover:-translate-y-0.5 flex flex-col justify-between group">
                        <div class="space-y-3">
                            <div class="flex items-center justify-between">
                                <div class="w-10 h-10 rounded-2xl flex items-center justify-center text-sm shadow-sm" style="background-color: ${t.color}15; color: ${t.color};">
                                    <i class="fa-solid fa-${t.icon}"></i>
                                </div>
                                <span class="badge-pill text-[10px] font-mono" style="background-color: ${t.color}15; color: ${t.color};">
                                    ${t.live_community_stats.community_reports_count} Reports
                                </span>
                            </div>
                            <div>
                                <h3 class="text-xs font-extrabold text-charcoal group-hover:text-charcoalHover">${t.title}</h3>
                                <p class="text-[11px] text-gray-500 mt-1 line-clamp-2 leading-relaxed">${t.summary}</p>
                            </div>
                        </div>
                        <div class="mt-4 pt-3 border-t border-borderMuted flex items-center justify-between text-[11px] font-semibold text-gray-400 group-hover:text-charcoal">
                            <span>Explore Guide & Evidence</span>
                            <i class="fa-solid fa-arrow-right text-[10px] transition-transform group-hover:translate-x-1"></i>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                console.error("Education load error:", e);
                grid.innerHTML = `<div class="text-xs text-gray-500 p-4">Could not load educational modules.</div>`;
            }
        }

        async function openEducationTopic(topicId) {
            try {
                const res = await fetch(`/api/community/education/${topicId}`);
                if (!res.ok) throw new Error("Topic not found");
                const data = await res.json();
                const t = data.topic;

                document.getElementById('eduModalVector').innerText = t.threat_vector.toUpperCase();
                document.getElementById('eduModalTitle').innerText = t.title;
                document.getElementById('eduModalSummary').innerText = t.summary;

                const iconEl = document.getElementById('eduModalIcon');
                iconEl.style.backgroundColor = `${t.color}15`;
                iconEl.style.color = t.color;
                iconEl.innerHTML = `<i class="fa-solid fa-${t.icon}"></i>`;

                document.getElementById('eduModalSigns').innerHTML = (t.common_warning_signs || []).map(s => `<li>${s}</li>`).join('');
                document.getElementById('eduModalConsequences').innerHTML = (t.potential_consequences || []).map(c => `<li>${c}</li>`).join('');
                document.getElementById('eduModalPrevention').innerHTML = (t.prevention_tips || []).map(p => `<li>${p}</li>`).join('');
                document.getElementById('eduModalActions').innerHTML = (t.recommended_actions || []).map(a => `<li>${a}</li>`).join('');

                const stats = t.live_community_stats || {};
                document.getElementById('eduModalStatsBadge').innerText = `${stats.community_reports_count || 0} Incident Records (₹${(stats.total_monetary_loss_inr || 0).toLocaleString()} Lost)`;

                const samplesEl = document.getElementById('eduModalSamples');
                const samples = stats.recent_incident_samples || [];
                if (samples.length > 0) {
                    samplesEl.innerHTML = samples.map(s => `
                        <div class="bg-surface p-2.5 rounded-xl border border-borderMuted flex items-center justify-between text-[11px]">
                            <span class="font-mono font-bold text-charcoal">${s.incident_ref}</span>
                            <span class="truncate max-w-xs text-gray-600">${s.incident_title}</span>
                            <span class="text-accentRed font-semibold">₹${s.amount_lost.toLocaleString()}</span>
                        </div>
                    `).join('');
                } else {
                    samplesEl.innerHTML = '<div class="text-[11px] text-gray-400 italic">No recent matching samples.</div>';
                }

                document.getElementById('educationModal').classList.remove('hidden');
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        function closeEducationModal() {
            document.getElementById('educationModal').classList.add('hidden');
        }

        // ==========================================
        // 4. THREAT RELATIONSHIP GRAPH (PROMPT 5 REQ 4)
        // ==========================================
        async function loadGlobalGraph() {
            renderGraphEndpoint('/api/community/graph?max_nodes=40');
        }

        async function renderGraphEndpoint(url) {
            const container = document.getElementById('graphCanvasContainer');
            const summaryEl = document.getElementById('graphSummaryText');

            container.innerHTML = `
                <div class="text-center text-gray-400 text-xs space-y-2">
                    <i class="fa-solid fa-spinner fa-spin text-xl"></i>
                    <div>Computing Graph Relationships...</div>
                </div>
            `;

            try {
                const res = await fetch(url);
                if (!res.ok) throw new Error("Failed to load graph data");
                const data = await res.json();

                if (!data.has_relationships || !data.nodes || data.nodes.length === 0) {
                    summaryEl.innerText = "0 Nodes • 0 Relationships";
                    container.innerHTML = `
                        <div class="text-center p-8 text-xs text-gray-500 space-y-2 max-w-md">
                            <div class="w-12 h-12 rounded-full bg-gray-100 text-gray-400 flex items-center justify-center text-xl mx-auto">
                                <i class="fa-solid fa-diagram-project"></i>
                            </div>
                            <div class="font-bold text-charcoal text-sm">No Corroborated Relationships Detected</div>
                            <p class="text-gray-400 leading-relaxed">
                                No shared domains, UPI receivers, or code repositories link this incident to other reports. No synthetic or decorative connections are generated.
                            </p>
                        </div>
                    `;
                    return;
                }

                summaryEl.innerText = `${data.nodes.length} Nodes • ${data.edges.length} Relationships mapped`;

                // Render lightweight interactive SVG graph
                const width = container.clientWidth || 800;
                const height = 440;
                const nodes = data.nodes;
                const edges = data.edges;

                // Simple layout circle calculation
                const nodePositions = {};
                const radius = Math.min(width, height) * 0.38;
                const centerX = width / 2;
                const centerY = height / 2;

                nodes.forEach((n, i) => {
                    const angle = (i / nodes.length) * 2 * Math.PI;
                    nodePositions[n.id] = {
                        x: centerX + radius * Math.cos(angle) + (Math.random() * 20 - 10),
                        y: centerY + radius * Math.sin(angle) + (Math.random() * 20 - 10)
                    };
                });

                let edgesSVG = edges.map(e => {
                    const src = nodePositions[e.source];
                    const tgt = nodePositions[e.target];
                    if (!src || !tgt) return '';
                    const isHighConf = e.confidence >= 0.95;
                    const strokeColor = isHighConf ? '#141518' : '#94A3B8';
                    const strokeDash = isHighConf ? '' : 'stroke-dasharray="4"';
                    return `
                        <line x1="${src.x}" y1="${src.y}" x2="${tgt.x}" y2="${tgt.y}" 
                              stroke="${strokeColor}" stroke-width="${isHighConf ? 2 : 1.5}" ${strokeDash} opacity="0.6" />
                    `;
                }).join('');

                let nodesSVG = nodes.map(n => {
                    const pos = nodePositions[n.id];
                    let fill = '#141518';
                    let r = 18;
                    if (n.node_type === 'domain') { fill = '#3B82F6'; r = 14; }
                    else if (n.node_type === 'phone_upi') { fill = '#F59E0B'; r = 14; }
                    else if (n.node_type === 'github_repo') { fill = '#8B5CF6'; r = 14; }
                    else if (n.node_type === 'campaign') { fill = '#10B981'; r = 16; }

                    const labelShort = (n.label || n.id).substring(0, 16);
                    return `
                        <g class="graph-node" onclick="handleGraphNodeClick('${n.id}', '${n.node_type}')">
                            <circle cx="${pos.x}" cy="${pos.y}" r="${r}" fill="${fill}" />
                            <text x="${pos.x}" y="${pos.y + r + 13}" font-family="Plus Jakarta Sans" font-size="10px" font-weight="600" fill="#334155" text-anchor="middle">
                                ${labelShort}
                            </text>
                        </g>
                    `;
                }).join('');

                container.innerHTML = `
                    <svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" class="w-full h-full">
                        <g>${edgesSVG}</g>
                        <g>${nodesSVG}</g>
                    </svg>
                `;
            } catch (err) {
                container.innerHTML = `<div class="text-xs text-gray-500 p-4">Graph rendering failed.</div>`;
            }
        }

        function handleGraphNodeClick(nodeId, nodeType) {
            if (nodeType === 'incident') {
                openIncidentModal(nodeId);
            } else if (nodeType === 'domain' || nodeType === 'phone_upi') {
                const clean = nodeId.replace(/^dom:/, '').replace(/^upi:/, '');
                searchByIndicator(clean);
            }
        }

        // ==========================================
        // 5. MODERATOR PORTAL LOGIC (PROMPT 5 REQ 2)
        // ==========================================
        function openModeratorModal() {
            document.getElementById('moderatorModal').classList.remove('hidden');
            if (activeModeratorKey) {
                document.getElementById('modAuthGate').classList.add('hidden');
                document.getElementById('modQueueContainer').classList.remove('hidden');
                loadModeratorQueue();
            } else {
                document.getElementById('modAuthGate').classList.remove('hidden');
                document.getElementById('modQueueContainer').classList.add('hidden');
            }
        }

        function closeModeratorModal() {
            document.getElementById('moderatorModal').classList.add('hidden');
        }

        async function authenticateModerator() {
            const key = document.getElementById('modKeyInput').value.trim();
            const errEl = document.getElementById('modAuthError');
            errEl.classList.add('hidden');

            try {
                const res = await fetch('/api/community/moderation/reports?page_size=1', {
                    headers: { 'X-Moderator-Key': key }
                });
                if (!res.ok) {
                    throw new Error("Invalid key");
                }
                activeModeratorKey = key;
                sessionStorage.setItem('factora_moderator_key', key);
                document.getElementById('modAuthGate').classList.add('hidden');
                document.getElementById('modQueueContainer').classList.remove('hidden');
                loadModeratorQueue();
            } catch (e) {
                errEl.classList.remove('hidden');
            }
        }

        function lockModeratorPortal() {
            activeModeratorKey = null;
            sessionStorage.removeItem('factora_moderator_key');
            document.getElementById('modAuthGate').classList.remove('hidden');
            document.getElementById('modQueueContainer').classList.add('hidden');
        }

        async function loadModeratorQueue() {
            const container = document.getElementById('modIncidentCardsList');
            container.innerHTML = `<div class="h-28 rounded-2xl skeleton"></div>`;

            const filterStatus = document.getElementById('modFilterStatus').value;
            let url = `/api/community/moderation/reports?page=1&page_size=20`;
            if (filterStatus !== 'all') {
                url += `&status=${encodeURIComponent(filterStatus)}`;
            }

            try {
                const res = await fetch(url, {
                    headers: { 'X-Moderator-Key': activeModeratorKey }
                });
                if (!res.ok) throw new Error("Auth failed");
                const data = await res.json();
                const reports = data.reports || [];

                if (reports.length === 0) {
                    container.innerHTML = `<div class="text-center py-8 text-xs text-gray-500">No reports found under this filter.</div>`;
                    return;
                }

                container.innerHTML = reports.map(r => `
                    <div class="bg-canvas border border-borderMuted rounded-2xl p-4 space-y-3 text-xs">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <span class="font-mono font-bold text-charcoal">${r.incident_ref}</span>
                                <span class="badge-pill bg-gray-200 text-charcoal font-bold text-[10px]">${r.verification_status}</span>
                                ${r.moderation_flag !== 'clean' ? `<span class="badge-pill bg-red-100 text-accentRed text-[10px] uppercase font-bold">${r.moderation_flag}</span>` : ''}
                            </div>
                            <span class="text-[11px] text-gray-400">${r.reported_at}</span>
                        </div>
                        <div>
                            <h4 class="font-bold text-gray-900">${r.incident_title}</h4>
                            <p class="text-gray-600 mt-1 line-clamp-2">${r.description}</p>
                        </div>
                        <div class="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-borderMuted">
                            <div class="flex items-center gap-2">
                                <button onclick="setIncidentStatus('${r.incident_ref}', 'CORROBORATED')" class="px-2.5 py-1 rounded-lg bg-emerald-100 text-emerald-800 hover:bg-emerald-200 font-semibold text-[11px]">
                                    Corroborate
                                </button>
                                <button onclick="setIncidentStatus('${r.incident_ref}', 'DISPUTED')" class="px-2.5 py-1 rounded-lg bg-amber-100 text-amber-800 hover:bg-amber-200 font-semibold text-[11px]">
                                    Dispute
                                </button>
                                <button onclick="setIncidentStatus('${r.incident_ref}', 'CLOSED')" class="px-2.5 py-1 rounded-lg bg-gray-200 text-gray-700 hover:bg-gray-300 font-semibold text-[11px]">
                                    Close
                                </button>
                            </div>
                            <button onclick="openIncidentModal('${r.incident_ref}')" class="px-3 py-1 rounded-full bg-surface border border-borderMuted hover:bg-gray-50 text-[11px] font-semibold">
                                Full Review
                            </button>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                container.innerHTML = `<div class="text-xs text-red-500 p-4">Session expired. Please re-authenticate.</div>`;
            }
        }

        async function setIncidentStatus(ref, newStatus) {
            const note = prompt(`Enter moderation notes for marking ${ref} as ${newStatus}:`, `Reviewed and updated to ${newStatus}`);
            if (note === null) return;

            try {
                const res = await fetch(`/api/community/moderation/review/${ref}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Moderator-Key': activeModeratorKey
                    },
                    body: JSON.stringify({
                        new_status: newStatus,
                        moderator_id: 'mod-active-session',
                        moderator_notes: note,
                        is_public_approved: true
                    })
                });
                if (!res.ok) throw new Error("Failed to update");
                alert(`Incident ${ref} updated to ${newStatus}!`);
                loadModeratorQueue();
                refreshDashboard();
                fetchFeedData();
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        // ==========================================
        // 6. COMMUNITY FEED (PART A & B)
        // ==========================================
        async function loadFeedFilterOptions() {
            try {
                const res = await fetch('/api/community/feed/filters');
                if (!res.ok) return;
                const data = await res.json();
                const typeSelect = document.getElementById('filterIncidentType');
                if (typeSelect && data.options && data.options.incident_types) {
                    typeSelect.innerHTML = '<option value="all">All Types</option>' + 
                        data.options.incident_types.map(t => `<option value="${t.type_id}">${t.display_name}</option>`).join('');
                }
            } catch (err) {
                console.error("Failed to load filter options", err);
            }
        }

        async function fetchFeedData() {
            const container = document.getElementById('activityFeedContainer');
            const emptyState = document.getElementById('feedEmptyState');

            container.innerHTML = `
                <div class="h-28 rounded-3xl skeleton"></div>
                <div class="h-28 rounded-3xl skeleton"></div>
            `;
            emptyState.classList.add('hidden');

            const category = document.getElementById('filterCategory').value;
            const riskLevel = document.getElementById('filterRiskLevel').value;
            const status = document.getElementById('filterStatus').value;
            const dateFilter = document.getElementById('filterDate').value;
            const incidentType = document.getElementById('filterIncidentType').value;
            const query = feedState.currentQuery;

            try {
                let url = '';
                if (feedState.isSearchMode && query) {
                    url = `/api/community/search?q=${encodeURIComponent(query)}&page=${feedState.page}&page_size=${feedState.pageSize}`;
                    if (category !== 'all') url += `&category=${encodeURIComponent(category)}`;
                    if (status !== 'all') url += `&verification_status=${encodeURIComponent(status)}`;
                } else {
                    url = `/api/community/feed?page=${feedState.page}&page_size=${feedState.pageSize}`;
                    if (category !== 'all') url += `&category=${encodeURIComponent(category)}`;
                    if (riskLevel !== 'all') url += `&risk_level=${encodeURIComponent(riskLevel)}`;
                    if (status !== 'all') url += `&verification_status=${encodeURIComponent(status)}`;
                    if (dateFilter !== 'all') url += `&date_filter=${encodeURIComponent(dateFilter)}`;
                    if (incidentType !== 'all') url += `&incident_type=${encodeURIComponent(incidentType)}`;
                    if (query) url += `&q=${encodeURIComponent(query)}`;
                }

                const res = await fetch(url);
                if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
                const data = await res.json();

                if (feedState.isSearchMode) {
                    renderSearchResults(data);
                } else {
                    renderFeedItems(data);
                }
            } catch (err) {
                console.error("Feed error:", err);
                container.innerHTML = `<div class="text-xs text-gray-500 p-8 text-center">Unable to load feed data.</div>`;
            }
        }

        function renderFeedItems(data) {
            const container = document.getElementById('activityFeedContainer');
            const emptyState = document.getElementById('feedEmptyState');
            const items = data.feed || [];

            feedState.totalItems = data.pagination ? data.pagination.total_items : items.length;
            feedState.totalPages = data.pagination ? data.pagination.total_pages : 1;
            updatePaginationUI(data.pagination);

            if (items.length === 0) {
                container.innerHTML = '';
                emptyState.classList.remove('hidden');
                return;
            }

            container.innerHTML = items.map(inc => renderIncidentCardHTML(inc, false)).join('');
        }

        function renderSearchResults(data) {
            const container = document.getElementById('activityFeedContainer');
            const emptyState = document.getElementById('feedEmptyState');
            const results = data.results || [];

            feedState.totalItems = data.pagination ? data.pagination.total_items : results.length;
            feedState.totalPages = data.pagination ? data.pagination.total_pages : 1;
            updatePaginationUI(data.pagination);

            const activeBanner = document.getElementById('activeSearchSummaryBanner');
            const queryText = document.getElementById('activeSearchQueryText');
            const countsText = document.getElementById('activeSearchCountsText');

            activeBanner.classList.remove('hidden');
            queryText.innerHTML = `Active Search: <strong class="text-charcoal">${data.query}</strong>`;
            countsText.innerHTML = `
                <span class="text-accentGreen">Exact: ${data.exact_matches_count || 0}</span>
                <span class="text-accentPurple">Correlated: ${data.related_matches_count || 0}</span>
                <span class="text-gray-500">Approx: ${data.approximate_matches_count || 0}</span>
            `;

            if (results.length === 0) {
                container.innerHTML = '';
                emptyState.classList.remove('hidden');
                return;
            }

            container.innerHTML = results.map(inc => renderIncidentCardHTML(inc, true)).join('');
        }

        function renderIncidentCardHTML(inc, isSearchResult = false) {
            let searchBadgeHTML = '';
            if (isSearchResult) {
                let badgeColor = '#EF4444';
                let badgeText = 'Exact Match';
                if (inc.match_type === 'related') {
                    badgeColor = '#8B5CF6';
                    badgeText = 'Correlated Syndicate';
                } else if (inc.match_type === 'approximate') {
                    badgeColor = '#6B7280';
                    badgeText = 'Approximate Match';
                }

                searchBadgeHTML = `
                    <div class="mb-2 p-2.5 rounded-xl bg-canvas border border-borderMuted text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div class="flex items-center gap-2">
                            <span class="badge-pill text-[10px]" style="background-color: ${badgeColor}15; color: ${badgeColor};">
                                ${badgeText}
                            </span>
                            <span class="text-[11px] text-gray-600">${inc.match_explanation || 'Matched search query'}</span>
                        </div>
                        <div class="shrink-0 text-right">
                            <span class="text-[10px] text-gray-400 font-semibold uppercase block">Relationship Confidence</span>
                            <span class="font-mono text-xs font-extrabold text-charcoal">${(inc.relationship_confidence * 100).toFixed(0)}%</span>
                        </div>
                    </div>
                `;
            }

            return `
                <div onclick="openIncidentModal('${inc.incident_ref}')" class="bg-surface rounded-3xl p-5 shadow-tactile border border-borderMuted hover:border-gray-400 cursor-pointer transition-all hover:-translate-y-0.5 space-y-3">
                    ${searchBadgeHTML}
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="font-mono text-xs font-bold text-gray-400">${inc.incident_ref}</span>
                            <span class="badge-pill" style="background-color: ${inc.category_color}15; color: ${inc.category_color};">
                                ${inc.category_name}
                            </span>
                            <span class="badge-pill font-bold" style="background-color: ${inc.risk_color}15; color: ${inc.risk_color};">
                                <i class="fa-solid fa-shield-virus"></i> ${inc.risk_level}
                            </span>
                            <span class="badge-pill bg-gray-100 text-charcoal border border-borderMuted text-[10px]">
                                ${inc.verification_status}
                            </span>
                        </div>
                        <div class="text-[11px] text-gray-400 font-medium">
                            <i class="fa-regular fa-clock"></i> ${inc.reported_at}
                        </div>
                    </div>

                    <div>
                        <h4 class="text-sm font-extrabold text-charcoal leading-snug">${inc.incident_title}</h4>
                        <p class="text-xs text-gray-600 mt-1 line-clamp-2 leading-relaxed">${inc.description}</p>
                    </div>

                    <div class="flex flex-wrap items-center justify-between pt-2 border-t border-borderMuted gap-2 text-xs">
                        <div class="flex items-center gap-4 text-gray-500">
                            <div>
                                <span class="text-gray-400 font-medium">Claimed:</span>
                                <strong class="text-charcoal">${inc.claimed_organization}</strong>
                            </div>
                            <div>
                                <span class="text-gray-400 font-medium">Loss:</span>
                                <strong class="${inc.amount_demanded_or_lost_inr > 0 ? 'text-accentRed' : 'text-gray-700'}">
                                    Rs. ${inc.amount_demanded_or_lost_inr.toLocaleString()}
                                </strong>
                            </div>
                        </div>

                        <div class="flex items-center gap-3">
                            <div class="flex items-center gap-1.5 text-[11px] font-semibold ${inc.related_incidents_count > 0 ? 'text-accentPurple' : 'text-gray-400'}">
                                <i class="fa-solid fa-link text-[10px]"></i>
                                <span>${inc.related_incidents_count} related</span>
                            </div>
                            <span class="text-[11px] font-semibold text-charcoal flex items-center gap-1 hover:underline">
                                <span>Details</span> <i class="fa-solid fa-arrow-right text-[9px]"></i>
                            </span>
                        </div>
                    </div>
                </div>
            `;
        }

        function updatePaginationUI(p) {
            if (!p) return;
            document.getElementById('currentPageIndicator').innerText = `Page ${p.page} of ${p.total_pages}`;
            document.getElementById('prevPageBtn').disabled = !p.has_prev;
            document.getElementById('nextPageBtn').disabled = !p.has_next;

            const startIdx = (p.page - 1) * p.page_size + 1;
            const endIdx = Math.min(p.page * p.page_size, p.total_items);
            document.getElementById('paginationRangeText').innerText = p.total_items > 0 ? 
                `Showing ${startIdx} to ${endIdx} of ${p.total_items} reports` : 
                `0 reports found`;
            document.getElementById('feedPaginationSummary').innerText = `${p.total_items} Total Indexed Incidents`;
        }

        function changeFeedPage(delta) {
            const newPage = feedState.page + delta;
            if (newPage >= 1 && newPage <= feedState.totalPages) {
                feedState.page = newPage;
                fetchFeedData();
                document.getElementById('feedSection').scrollIntoView({ behavior: 'smooth' });
            }
        }

        function applyFeedFilters() {
            feedState.page = 1;
            fetchFeedData();
        }

        function executeFeedSearch() {
            const input = document.getElementById('feedSearchInput');
            const q = input.value.trim();
            if (!q) {
                clearFeedSearch();
                return;
            }

            feedState.isSearchMode = true;
            feedState.currentQuery = q;
            feedState.page = 1;

            document.getElementById('clearFeedSearchBtn').classList.remove('hidden');
            fetchFeedData();
        }

        function clearFeedSearch() {
            const input = document.getElementById('feedSearchInput');
            input.value = '';
            feedState.isSearchMode = false;
            feedState.currentQuery = '';
            feedState.page = 1;

            document.getElementById('clearFeedSearchBtn').classList.add('hidden');
            document.getElementById('activeSearchSummaryBanner').classList.add('hidden');
            fetchFeedData();
        }

        function resetAllFeedFilters() {
            document.getElementById('filterCategory').value = 'all';
            document.getElementById('filterRiskLevel').value = 'all';
            document.getElementById('filterStatus').value = 'all';
            document.getElementById('filterDate').value = 'all';
            document.getElementById('filterIncidentType').value = 'all';
            clearFeedSearch();
        }

        function searchByIndicator(indicator) {
            const input = document.getElementById('feedSearchInput');
            if (input) {
                input.value = indicator;
                executeFeedSearch();
                document.getElementById('feedSection').scrollIntoView({ behavior: 'smooth' });
            }
        }

        // ==========================================
        // 7. INCIDENT DETAIL MODAL
        // ==========================================
        async function openIncidentModal(ref) {
            try {
                const res = await fetch(`/api/community/incidents/${ref}`);
                if (!res.ok) throw new Error("Could not load incident details");
                const inc = await res.json();
                currentModalIncident = inc;

                document.getElementById('modalRef').innerText = inc.incident_ref;
                document.getElementById('modalTitle').innerText = inc.incident_title;
                document.getElementById('modalCategory').innerText = inc.scam_type.replace(/_/g, ' ').toUpperCase();
                document.getElementById('modalStatus').innerText = inc.verification_status;
                document.getElementById('modalDate').innerText = inc.reported_at;
                document.getElementById('modalLoss').innerText = `Rs. ${inc.amount_demanded_or_lost_inr.toLocaleString()}`;
                document.getElementById('modalDescription').innerText = inc.description;

                const indContainer = document.getElementById('modalIndicators');
                let indicators = [];
                if (inc.scammer_contacts) indicators = indicators.concat(inc.scammer_contacts.map(c => ({ text: c, icon: 'phone' })));
                if (inc.scammer_links) indicators = indicators.concat(inc.scammer_links.map(l => ({ text: l, icon: 'globe' })));

                if (indicators.length > 0) {
                    indContainer.innerHTML = indicators.map(ind => `
                        <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-xl bg-canvas border border-borderMuted font-mono text-[11px] text-charcoal">
                            <i class="fa-solid fa-${ind.icon} text-gray-400"></i> ${ind.text}
                        </span>
                    `).join('');
                } else {
                    indContainer.innerHTML = '<span class="text-gray-400 italic text-xs">No explicit links or handles identified.</span>';
                }

                // Load graph neighborhood for this incident
                renderGraphEndpoint(`/api/community/graph/${inc.incident_ref}?max_nodes=15`);

                document.getElementById('incidentModal').classList.remove('hidden');
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        function closeIncidentModal() {
            document.getElementById('incidentModal').classList.add('hidden');
            currentModalIncident = null;
        }

        function copyGeneratedFIRDraft() {
            if (!currentModalIncident) return;
            const draft = `
FORMAL COMPLAINT UNDER THE INFORMATION TECHNOLOGY ACT, 2000
Subject: Reporting of Cybercrime Incident Ref: ${currentModalIncident.incident_ref}

Incident Title: ${currentModalIncident.incident_title}
Threat Category: ${currentModalIncident.scam_type}
Impersonated Entity: ${currentModalIncident.claimed_organization || 'Unspecified'}
Reported Date: ${currentModalIncident.reported_at}
Reported Loss: Rs. ${currentModalIncident.amount_demanded_or_lost_inr}

Description:
${currentModalIncident.description}

Identified Suspect Handles/Links:
${(currentModalIncident.scammer_contacts || []).join(', ')}
${(currentModalIncident.scammer_links || []).join(', ')}

Submitted via FACTORA — From Victim to Defender.
            `.trim();

            navigator.clipboard.writeText(draft).then(() => {
                const btn = document.getElementById('copyFirBtn');
                btn.innerHTML = `<i class="fa-solid fa-check text-accentGreen"></i> Draft Copied!`;
                setTimeout(() => {
                    btn.innerHTML = `<i class="fa-regular fa-copy"></i> Copy Pre-Filled FIR Draft`;
                }, 2000);
            });
        }

        function showError(msg) {
            const banner = document.getElementById('errorBanner');
            const messageEl = document.getElementById('errorMessage');
            if (banner && messageEl) {
                messageEl.innerText = msg;
                banner.classList.remove('hidden');
            }
        }

        function hideError() {
            const banner = document.getElementById('errorBanner');
            if (banner) banner.classList.add('hidden');
        }

        document.addEventListener('DOMContentLoaded', () => {
            refreshDashboard();
            loadThreatAlerts();
            loadFeedFilterOptions();
            fetchFeedData();
            loadEducationCentre();
            loadGlobalGraph();
            updateMyReportsCount();
        });
    </script>
</body>
</html>
"""
