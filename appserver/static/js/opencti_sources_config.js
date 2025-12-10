// Entry point for the “Configuration” dashboard (opencti_sources_config.xml).
// Delegates all behavior to the main correlations controller to keep
// naming aligned between the dashboard and its JS.
require([
  'app/SA-OpenCTIThreatMatch/js/opencti_correlations_dashboard',
], function() {
  // No-op; the required module bootstraps itself.
});
