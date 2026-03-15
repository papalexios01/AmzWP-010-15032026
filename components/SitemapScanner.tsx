/**
 * ============================================================================
 * SitemapScanner | Enterprise Content Discovery v100.0
 * ============================================================================
 * Features:
 * - Multiple discovery methods (Sitemap, WP API, Manual)
 * - Real-time progress feedback
 * - Smart error handling with actionable suggestions
 * - Filtering and search
 * - Batch processing integration
 * - Deep content audit
 * ============================================================================
 */

import React, { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { BlogPost, AppConfig, SitemapState } from '../types';
import { 
  fetchAndParseSitemap, 
  fetchPostsFromWordPressAPI,
  validateManualUrl, 
  createBlogPostFromUrl,
  calculatePostPriority,
  fetchPageContent,
  getProxyStats,
} from '../utils';
import { toast } from 'sonner';
import { useVirtualizer } from '@tanstack/react-virtual';

// ============================================================================
// TYPES
// ============================================================================

interface SitemapScannerProps {
  onPostSelect: (post: BlogPost) => void;
  savedState: SitemapState;
  onStateChange: (state: SitemapState) => void;
  config: AppConfig;
}

type ScanStatus = 'idle' | 'scanning' | 'auditing' | 'complete' | 'error';
type DiscoveryMethod = 'sitemap' | 'wordpress' | 'manual';
type FilterTab = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'monetized';

// ============================================================================
// TOAST HELPER
// ============================================================================

const showToast = (message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info') => {
    toast[type](message);
};

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export const SitemapScanner: React.FC<SitemapScannerProps> = ({
  onPostSelect,
  savedState,
  onStateChange,
  config,
}) => {
  // ========== STATE ==========
  const [sitemapUrl, setSitemapUrl] = useState(savedState.url || '');
  const [posts, setPosts] = useState<BlogPost[]>(savedState.posts || []);
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [filterTab, setFilterTab] = useState<FilterTab>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showManualAdd, setShowManualAdd] = useState(false);
  const [manualUrl, setManualUrl] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [auditProgress, setAuditProgress] = useState({ current: 0, total: 0 });
  const [discoveryMethod, setDiscoveryMethod] = useState<DiscoveryMethod>('sitemap');

  // ========== REFS ==========
  const abortControllerRef = useRef<AbortController | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);

  // ========== SYNC STATE ==========
  useEffect(() => {
    if (posts.length > 0 || sitemapUrl) {
      onStateChange({
        url: sitemapUrl,
        posts,
        lastScanned: Date.now(),
      });
    }
  }, [posts, sitemapUrl, onStateChange]);

  // ========== FILTERED POSTS ==========
  const filteredPosts = useMemo(() => {
    let result = [...posts];

    if (filterTab !== 'all') {
      if (filterTab === 'monetized') {
        result = result.filter(p => p.monetizationStatus === 'monetized');
      } else {
        result = result.filter(p => p.priority === filterTab && p.monetizationStatus === 'opportunity');
      }
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      result = result.filter(p => 
        p.title.toLowerCase().includes(query) || 
        p.url.toLowerCase().includes(query)
      );
    }

    return result;
  }, [posts, filterTab, searchQuery]);

  const virtualizer = useVirtualizer({
    count: filteredPosts.length,
    getScrollElement: () => scrollContainerRef.current,
    estimateSize: () => 80,
    overscan: 10,
  });

  // ========== STATS ==========
  const stats = useMemo(() => ({
    total: posts.length,
    critical: posts.filter(p => p.priority === 'critical' && p.monetizationStatus === 'opportunity').length,
    high: posts.filter(p => p.priority === 'high' && p.monetizationStatus === 'opportunity').length,
    medium: posts.filter(p => p.priority === 'medium' && p.monetizationStatus === 'opportunity').length,
    low: posts.filter(p => p.priority === 'low' && p.monetizationStatus === 'opportunity').length,
    monetized: posts.filter(p => p.monetizationStatus === 'monetized').length,
  }), [posts]);

  // ========== SITEMAP DISCOVERY ==========
  const handleSitemapFetch = async () => {
    const trimmedUrl = sitemapUrl.trim();
    if (!trimmedUrl) {
      showToast('Please enter a domain or sitemap URL', 'warning');
      return;
    }

    abortControllerRef.current?.abort();
    abortControllerRef.current = new AbortController();

    setStatus('scanning');
    setErrorMessage(null);
    
    try {
      const discoveredPosts = await fetchAndParseSitemap(trimmedUrl, config);
      
      if (discoveredPosts.length === 0) {
        throw new Error('No posts found');
      }
      
      setPosts(discoveredPosts);
      setStatus('complete');
      showToast(`✓ Found ${discoveredPosts.length} pages!`, 'success');
      
    } catch (error: any) {
      setErrorMessage(error.message || 'Discovery failed');
      setStatus('error');
      showToast('Discovery failed - see error details below', 'error');
    }
  };

  // ========== WORDPRESS API DISCOVERY ==========
  const handleWordPressAPI = async () => {
    const targetUrl = sitemapUrl.trim() || config.wpUrl;
    if (!targetUrl) {
      showToast('Enter a domain name first', 'warning');
      return;
    }

    setStatus('scanning');
    setErrorMessage(null);
    setDiscoveryMethod('wordpress');
    setAuditProgress({ current: 0, total: 0 });

    try {
      const discoveredPosts = await fetchPostsFromWordPressAPI(
        config,
        (current, total) => {
          setAuditProgress({ current, total });
        },
        targetUrl
      );

      setPosts(discoveredPosts);
      if (!sitemapUrl.trim()) setSitemapUrl(targetUrl);
      setStatus('complete');
      showToast(`Found ${discoveredPosts.length} posts via WordPress API!`, 'success');

    } catch (error: any) {
      setErrorMessage(`WordPress API Error: ${error.message}`);
      setStatus('error');
      showToast('WordPress API failed - try Sitemap Discover instead', 'error');
    }
  };

  // ========== MANUAL ADD ==========
  const handleManualAdd = () => {
    const validation = validateManualUrl(manualUrl);
    
    if (!validation.isValid) {
      showToast(validation.error || 'Invalid URL', 'error');
      return;
    }

        if (validation.normalizedUrl && posts.some(p => p.url.toLowerCase() === validation.normalizedUrl!.toLowerCase())) {
      showToast('URL already in list', 'warning');
      return;
    }

    const newPost = createBlogPostFromUrl(validation.normalizedUrl!, posts.length);
    setPosts(prev => [newPost, ...prev]);
    setManualUrl('');
    setShowManualAdd(false);
    showToast('URL added successfully', 'success');
  };

  // ========== DEEP AUDIT ==========
  const runDeepAudit = async () => {
    if (posts.length === 0) return;
    
    setStatus('auditing');
    setAuditProgress({ current: 0, total: posts.length });
    
    const updatedPosts = [...posts];
    let completed = 0;

    // Concurrent processing with PQueue (5 workers)
    const PQueue = (await import('p-queue')).default;
    const queue = new PQueue({ concurrency: 5 });

    await Promise.all(
      updatedPosts.map((post, i) =>
        queue.add(async () => {
          try {
            const { content } = await fetchPageContent(config, post.url);
            const { priority, type, status: monetizationStatus } = calculatePostPriority(
              post.title,
              content
            );
            
            updatedPosts[i] = {
              ...updatedPosts[i],
              priority,
              postType: type,
              monetizationStatus,
            };
          } catch {}
          
          completed++;
          setAuditProgress({ current: completed, total: posts.length });
        })
      )
    );

    setPosts(updatedPosts);
    setStatus('complete');
    showToast('Content audit complete!', 'success');
  };

  // ========== DEBUG INFO ==========
  const showDebugInfo = () => {
    const stats = getProxyStats();
    alert(`Proxy Statistics:\n${JSON.stringify(stats, null, 2)}`);
  };

  // ========== RENDER ==========
  return (
    <div className="h-full flex flex-col bg-dark-950">
      {/* ========== HEADER ========== */}
      <header className="flex-shrink-0 p-6 md:p-8 border-b border-dark-800 bg-dark-900/50">
        <div className="max-w-6xl mx-auto">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-3xl md:text-4xl font-black text-white tracking-tight">
                Content Discovery
              </h1>
              <p className="text-gray-500 text-sm mt-1">
                Find and analyze your content for monetization opportunities
              </p>
            </div>
            
            {/* Debug Button */}
            <button
              onClick={showDebugInfo}
              className="text-gray-600 hover:text-gray-400 text-xs"
              title="Show debug info"
            >
              <i className="fa-solid fa-bug" />
            </button>
          </div>
          
          {/* ========== SEARCH FORM ========== */}
          <div className="flex gap-3 flex-wrap">
            <div className="flex-1 min-w-[280px]">
              <input
                type="text"
                value={sitemapUrl}
                onChange={e => setSitemapUrl(e.target.value)}
                placeholder="Enter domain (example.com) or full sitemap URL"
                className="w-full bg-dark-800 border border-dark-700 rounded-2xl px-6 py-4 text-white placeholder-gray-500 focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 outline-none transition-all"
                disabled={status === 'scanning' || status === 'auditing'}
                onKeyDown={e => e.key === 'Enter' && handleSitemapFetch()}
              />
            </div>
            
            {/* Sitemap Discover Button */}
            <button
              onClick={handleSitemapFetch}
              disabled={status === 'scanning' || status === 'auditing' || !sitemapUrl.trim()}
              className="px-8 py-4 bg-gradient-to-r from-brand-600 to-emerald-600 hover:from-brand-500 hover:to-emerald-500 text-white font-black rounded-2xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 shadow-xl hover:shadow-brand-500/25"
            >
              {status === 'scanning' ? (
                <>
                  <i className="fa-solid fa-spinner fa-spin" />
                  {auditProgress.total > 0
                    ? `Fetching ${auditProgress.current}/${auditProgress.total}...`
                    : 'Scanning...'}
                </>
              ) : status === 'auditing' ? (
                <>
                  <i className="fa-solid fa-spinner fa-spin" />
                  Auditing {auditProgress.current}/{auditProgress.total}
                </>
              ) : (
                <>
                  <i className="fa-solid fa-satellite-dish" />
                  Discover
                </>
              )}
            </button>

            {/* WordPress API Button */}
            <button
              onClick={handleWordPressAPI}
              disabled={status === 'scanning' || status === 'auditing' || (!sitemapUrl.trim() && !config.wpUrl)}
              className="px-6 py-4 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-2xl transition-all disabled:opacity-50 flex items-center gap-2"
              title="Fetch ALL posts from WordPress REST API (works with any WordPress site)"
            >
              {status === 'scanning' && discoveryMethod === 'wordpress' ? (
                <>
                  <i className="fa-solid fa-spinner fa-spin" />
                  {auditProgress.total > 0
                    ? `${auditProgress.current}/${auditProgress.total}`
                    : 'Fetching...'}
                </>
              ) : (
                <>
                  <i className="fa-brands fa-wordpress text-lg" />
                  <span className="hidden md:inline">WP API</span>
                </>
              )}
            </button>

            {/* Manual Add Button */}
            <button
              onClick={() => setShowManualAdd(true)}
              disabled={status === 'scanning' || status === 'auditing'}
              className="px-6 py-4 bg-dark-800 hover:bg-dark-700 text-white font-bold rounded-2xl transition-all border border-dark-700 hover:border-green-500/50 disabled:opacity-50 flex items-center gap-2"
            >
              <i className="fa-solid fa-plus" />
              <span className="hidden md:inline">Add URL</span>
            </button>
          </div>

          {/* ========== ERROR MESSAGE ========== */}
          {errorMessage && (
            <div className="mt-4 p-4 bg-red-500/10 border border-red-500/30 rounded-2xl">
              <div className="flex items-start gap-3">
                <i className="fa-solid fa-exclamation-triangle text-red-400 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm text-red-400 font-medium">Discovery Error</p>
                  <p className="text-xs text-gray-400 mt-1">{errorMessage}</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      onClick={handleWordPressAPI}
                      className="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 text-xs font-bold rounded-lg transition-all"
                    >
                      Try WordPress API →
                    </button>
                    <button
                      onClick={() => setShowManualAdd(true)}
                      className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 text-green-400 text-xs font-bold rounded-lg transition-all"
                    >
                      Add URLs Manually →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </header>

      {/* ========== FILTER TABS ========== */}
      {posts.length > 0 && (
        <div className="flex-shrink-0 border-b border-dark-800 bg-dark-900/30">
          <div className="max-w-6xl mx-auto px-6 md:px-8">
            <div className="flex gap-2 overflow-x-auto py-4 scrollbar-hide">
              {[
                { id: 'all' as FilterTab, label: 'All', count: stats.total, icon: 'fa-layer-group' },
                { id: 'critical' as FilterTab, label: 'Critical', count: stats.critical, icon: 'fa-fire', color: 'red' },
                { id: 'high' as FilterTab, label: 'High', count: stats.high, icon: 'fa-arrow-up', color: 'orange' },
                { id: 'medium' as FilterTab, label: 'Medium', count: stats.medium, icon: 'fa-minus', color: 'yellow' },
                { id: 'low' as FilterTab, label: 'Low', count: stats.low, icon: 'fa-arrow-down', color: 'green' },
                { id: 'monetized' as FilterTab, label: 'Monetized', count: stats.monetized, icon: 'fa-check', color: 'purple' },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setFilterTab(tab.id)}
                  className={`px-4 py-2 rounded-xl text-xs font-black uppercase tracking-wider transition-all flex items-center gap-2 whitespace-nowrap ${
                    filterTab === tab.id
                      ? 'bg-brand-500 text-white shadow-lg shadow-brand-500/25'
                      : 'bg-dark-800 text-gray-400 hover:bg-dark-700 hover:text-white'
                  }`}
                >
                  <i className={`fa-solid ${tab.icon}`} />
                  {tab.label}
                  <span className={`px-2 py-0.5 rounded-full text-[10px] ${
                    filterTab === tab.id ? 'bg-white/20' : 'bg-dark-700'
                  }`}>
                    {tab.count}
                  </span>
                </button>
              ))}
              
              {/* Deep Audit Button */}
              <button
                onClick={runDeepAudit}
                disabled={status === 'auditing' || posts.length === 0}
                className="ml-auto px-4 py-2 bg-violet-500/20 hover:bg-violet-500/30 text-violet-400 rounded-xl text-xs font-bold transition-all disabled:opacity-50 flex items-center gap-2"
              >
                <i className="fa-solid fa-microscope" />
                Deep Audit
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========== ACTION GUIDANCE PANEL ========== */}
      {posts.length > 0 && (stats.critical > 0 || stats.high > 0) && filterTab === 'all' && (
        <div className="flex-shrink-0 bg-dark-900/60 border-b border-dark-800">
          <div className="max-w-6xl mx-auto px-6 md:px-8 py-5">
            <div className="bg-gradient-to-r from-emerald-500/10 via-dark-800/50 to-blue-500/10 border border-dark-700 rounded-2xl p-5">
              <div className="flex items-start gap-4">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <i className="fa-solid fa-lightbulb text-emerald-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <h4 className="text-white font-bold text-sm mb-2">Action Plan: Monetize Your Content</h4>
                  <div className="space-y-2">
                    {stats.critical > 0 && (
                      <div className="flex items-start gap-2">
                        <span className="w-5 h-5 rounded-md bg-red-500/20 text-red-400 flex items-center justify-center flex-shrink-0 text-[10px] font-black mt-0.5">1</span>
                        <p className="text-gray-400 text-xs leading-relaxed">
                          <span className="text-red-400 font-bold">{stats.critical} critical posts</span> are product reviews, comparisons, or "best of" lists with
                          <span className="text-white font-semibold"> zero affiliate links</span>. Click on each to scan and add product boxes.
                        </p>
                      </div>
                    )}
                    {stats.high > 0 && (
                      <div className="flex items-start gap-2">
                        <span className="w-5 h-5 rounded-md bg-orange-500/20 text-orange-400 flex items-center justify-center flex-shrink-0 text-[10px] font-black mt-0.5">{stats.critical > 0 ? '2' : '1'}</span>
                        <p className="text-gray-400 text-xs leading-relaxed">
                          <span className="text-orange-400 font-bold">{stats.high} high-priority posts</span> mention specific brands or products. Open each,
                          run <span className="text-white font-semibold">Deep Scan</span>, then <span className="text-white font-semibold">Auto-Deploy All</span> to place product boxes.
                        </p>
                      </div>
                    )}
                    {stats.medium > 0 && (
                      <div className="flex items-start gap-2">
                        <span className="w-5 h-5 rounded-md bg-yellow-500/20 text-yellow-400 flex items-center justify-center flex-shrink-0 text-[10px] font-black mt-0.5">{(stats.critical > 0 ? 1 : 0) + (stats.high > 0 ? 1 : 0) + 1}</span>
                        <p className="text-gray-400 text-xs leading-relaxed">
                          <span className="text-yellow-400 font-bold">{stats.medium} medium posts</span> are guides or tutorials that could include relevant product recommendations.
                        </p>
                      </div>
                    )}
                    <div className="flex items-start gap-2 pt-1">
                      <span className="w-5 h-5 rounded-md bg-blue-500/20 text-blue-400 flex items-center justify-center flex-shrink-0 text-[10px] font-black mt-0.5"><i className="fa-solid fa-arrow-right text-[8px]" /></span>
                      <p className="text-gray-400 text-xs leading-relaxed">
                        <span className="text-blue-400 font-bold">Quick workflow:</span> Filter by
                        <button onClick={() => setFilterTab('critical')} className="text-red-400 font-bold underline underline-offset-2 mx-1 hover:text-red-300">Critical</button>
                        &#8594; Open post &#8594; Scan &#8594; Auto-Deploy All &#8594; Deploy Live
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========== POST LIST ========== */}
      <div className="flex-1 overflow-y-auto" ref={scrollContainerRef}>
        <div className="max-w-6xl mx-auto p-6 md:p-8">
          {posts.length === 0 ? (
            <div className="py-20 text-center">
              <div className="w-24 h-24 mx-auto mb-6 rounded-3xl bg-dark-800 flex items-center justify-center">
                <i className="fa-solid fa-map text-4xl text-dark-600" />
              </div>
              <h2 className="text-2xl font-black text-white mb-2">No Content Discovered</h2>
              <p className="text-gray-500 max-w-md mx-auto mb-6">
                Enter your domain above and click "Discover" to scan your sitemap,
                or use "WP API" if you have WordPress credentials configured.
              </p>
              <div className="flex justify-center gap-3">
                <button
                  onClick={() => setSitemapUrl('example.com')}
                  className="px-4 py-2 bg-dark-800 hover:bg-dark-700 text-gray-400 hover:text-white rounded-lg text-sm transition-all"
                >
                  Try example.com
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Search Bar */}
              <div className="flex gap-4 mb-6">
                <div className="flex-1 relative">
                  <i className="fa-solid fa-search absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Search posts by title or URL..."
                    className="w-full bg-dark-800 border border-dark-700 rounded-xl pl-12 pr-4 py-3 text-white placeholder-gray-500 focus:border-brand-500 outline-none"
                  />
                </div>
                <div className="text-sm text-gray-500 flex items-center">
                  Showing {filteredPosts.length} of {posts.length}
                </div>
              </div>

              {/* Posts Grid - Virtualized */}
              <div
                style={{ height: `${virtualizer.getTotalSize()}px`, width: '100%', position: 'relative' }}
              >
                {virtualizer.getVirtualItems().map(virtualRow => {
                  const post = filteredPosts[virtualRow.index];
                  return (
                    <div
                      key={post.id}
                      style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        width: '100%',
                        height: `${virtualRow.size}px`,
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                      className="pb-3"
                    >
                      <div
                        onClick={() => onPostSelect(post)}
                        className="p-4 md:p-5 bg-dark-800 hover:bg-dark-750 border border-dark-700 hover:border-brand-500/50 rounded-2xl cursor-pointer transition-all group h-full"
                      >
                        <div className="flex items-center gap-4">
                          {/* Priority Badge */}
                          <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${
                            post.monetizationStatus === 'monetized'
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : post.priority === 'critical'
                              ? 'bg-red-500/20 text-red-400'
                              : post.priority === 'high'
                              ? 'bg-orange-500/20 text-orange-400'
                              : post.priority === 'medium'
                              ? 'bg-yellow-500/20 text-yellow-400'
                              : 'bg-slate-500/20 text-slate-400'
                          }`}>
                            <i className={`fa-solid ${
                              post.monetizationStatus === 'monetized' ? 'fa-check-double' :
                              post.priority === 'critical' ? 'fa-fire' :
                              post.priority === 'high' ? 'fa-arrow-trend-up' :
                              'fa-dollar-sign'
                            } text-lg`} />
                          </div>

                          {/* Content */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-0.5">
                              <h3 className="font-bold text-white group-hover:text-brand-400 transition-colors truncate">
                                {post.title}
                              </h3>
                            </div>
                            <div className="flex items-center gap-3 mt-1">
                              <a
                                href={post.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                className="text-xs text-gray-500 hover:text-brand-400 truncate underline decoration-dotted underline-offset-2"
                              >
                                {post.url}
                              </a>
                              {post.monetizationStatus === 'opportunity' && post.priority !== 'low' && (
                                <span className="hidden md:inline-flex text-[9px] font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded whitespace-nowrap">
                                  Needs product boxes
                                </span>
                              )}
                            </div>
                          </div>

                          {/* Type Badge */}
                          <div className={`hidden md:block px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-wider ${
                            post.postType === 'review' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                            post.postType === 'listicle' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                            post.postType === 'comparison' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' :
                            post.postType === 'how-to' ? 'bg-teal-500/10 text-teal-400 border border-teal-500/20' :
                            'bg-dark-700 text-gray-400'
                          }`}>
                            {post.postType}
                          </div>

                          {/* Priority Indicator */}
                          {post.monetizationStatus === 'opportunity' && (
                            <div className={`hidden md:block px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-wider ${
                              post.priority === 'critical' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                              post.priority === 'high' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                              post.priority === 'medium' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' :
                              'bg-dark-700 text-gray-500'
                            }`}>
                              {post.priority}
                            </div>
                          )}

                          {/* Arrow */}
                          <div className="text-gray-600 group-hover:text-brand-400 group-hover:translate-x-1 transition-all">
                            <i className="fa-solid fa-chevron-right" />
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ========== MANUAL ADD MODAL ========== */}
      {showManualAdd && (
        <div 
          className="fixed inset-0 z-[100] bg-black/90 backdrop-blur-xl flex items-center justify-center p-4"
          onClick={e => e.target === e.currentTarget && setShowManualAdd(false)}
        >
          <div className="bg-dark-900 border border-dark-700 rounded-3xl p-8 max-w-lg w-full shadow-2xl">
            <h2 className="text-2xl font-black text-white mb-2">Add URL Manually</h2>
            <p className="text-sm text-gray-500 mb-6">
              Enter the full URL of a page you want to monetize
            </p>
            
            <input
              type="text"
              value={manualUrl}
              onChange={e => setManualUrl(e.target.value)}
              placeholder="https://example.com/blog-post-title"
              className="w-full bg-dark-800 border border-dark-700 rounded-xl px-4 py-4 text-white placeholder-gray-500 focus:border-brand-500 outline-none mb-4"
              autoFocus
              onKeyDown={e => e.key === 'Enter' && handleManualAdd()}
            />
            
            <div className="flex gap-3">
              <button
                onClick={() => setShowManualAdd(false)}
                className="flex-1 px-6 py-4 bg-dark-800 text-white font-bold rounded-xl hover:bg-dark-700 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleManualAdd}
                className="flex-1 px-6 py-4 bg-brand-600 hover:bg-brand-500 text-white font-black rounded-xl transition-all"
              >
                Add URL
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SitemapScanner;
