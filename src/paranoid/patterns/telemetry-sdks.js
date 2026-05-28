'use strict';

/**
 * Curated list of telemetry, analytics, and crash-reporting SDKs that
 * Occasio deliberately does not depend on. The self-audit scanner checks
 * for these in two places:
 *
 *   - SOURCE_PATTERNS: regex matches over .js files in src/ and bin/.
 *     Used to catch direct API calls (Sentry.init, analytics.track, etc).
 *   - PACKAGE_NAMES: npm package identifiers checked against
 *     package.json dependencies (runtime and dev). A presence in deps is
 *     a red flag even if the source does not call the SDK.
 *
 * Adding to this list is encouraged. New SDKs that ship telemetry by
 * default belong here so the regression test catches accidental adoption
 * in future contributions.
 *
 * The list is descriptive, not exhaustive. Patterns target unique
 * signatures (function names, vendor namespaces) rather than common
 * English words to keep the false-positive rate near zero.
 */

const SOURCE_PATTERNS = [
  // OpenTelemetry
  { re: /@opentelemetry\//,                    label: 'opentelemetry'        },
  { re: /\bopentelemetry-/,                    label: 'opentelemetry-legacy' },

  // Segment
  { re: /\banalytics\.identify\s*\(/,          label: 'segment-identify'     },
  { re: /\banalytics\.track\s*\(/,             label: 'segment-track'        },
  { re: /['"]@segment\/analytics/,             label: 'segment-pkg'          },

  // Mixpanel
  { re: /\bmixpanel-browser/,                  label: 'mixpanel-browser'     },
  { re: /\bmixpanel\.track\s*\(/,              label: 'mixpanel-track'       },
  { re: /\bmp_track\b/,                        label: 'mixpanel-mp_track'    },

  // PostHog
  { re: /\bposthog-/,                          label: 'posthog-legacy'       },
  { re: /\bposthog\.capture\s*\(/,             label: 'posthog-capture'      },

  // Amplitude
  { re: /\bamplitude\.getInstance\s*\(/,       label: 'amplitude'            },
  { re: /['"]@amplitude\//,                    label: 'amplitude-pkg'        },

  // Heap
  { re: /\bheap\.identify\s*\(/,               label: 'heap-identify'        },
  { re: /\bheap\.track\s*\(/,                  label: 'heap-track'           },

  // Datadog
  { re: /['"]@datadog\//,                      label: 'datadog'              },
  { re: /\bdd-trace\b/,                        label: 'dd-trace'             },
  { re: /\bdatadog-metrics\b/,                 label: 'datadog-metrics'      },

  // New Relic
  { re: /['"]@newrelic\//,                     label: 'newrelic'             },
  { re: /\bnewrelic\.recordCustomEvent\s*\(/,  label: 'newrelic-record'      },

  // Sentry
  { re: /['"]@sentry\//,                       label: 'sentry'               },
  { re: /\bSentry\.init\s*\(/,                 label: 'sentry-init'          },
  { re: /\bSentry\.captureException\s*\(/,     label: 'sentry-capture'       },

  // Microsoft Application Insights
  { re: /\bapplicationinsights\b/,             label: 'applicationinsights'  },
  { re: /\bApplicationInsights\b/,             label: 'applicationinsights'  },

  // Plausible / Fathom / Simple Analytics
  { re: /\bplausible\.trackEvent\s*\(/,        label: 'plausible'            },
  { re: /['"]plausible-tracker['"]/,           label: 'plausible-pkg'        },
  { re: /['"]@fathom-analytics\//,             label: 'fathom-analytics'     },
  { re: /['"]simple-analytics\b/,              label: 'simple-analytics'     },

  // Rollbar, Bugsnag, LogRocket, FullStory
  { re: /['"]@rollbar\//,                      label: 'rollbar'              },
  { re: /\bRollbar\.init\s*\(/,                label: 'rollbar-init'         },
  { re: /\bbugsnag-/,                          label: 'bugsnag-legacy'       },
  { re: /\bBugsnag\.start\s*\(/,               label: 'bugsnag-start'        },
  { re: /\blogrocket-/,                        label: 'logrocket-legacy'     },
  { re: /\bLogRocket\.init\s*\(/,              label: 'logrocket-init'       },
  { re: /\bfullstory-/,                        label: 'fullstory-legacy'     },

  // Google Analytics
  { re: /\bgoogleanalytics\b/,                 label: 'google-analytics'     },
  { re: /\bgtag\s*\(/,                         label: 'google-gtag'          },

  // Raygun, Honeycomb, Lightstep
  { re: /\braygun\b/i,                         label: 'raygun'               },
  { re: /['"]@honeycombio\//,                  label: 'honeycomb'            },
  { re: /['"]lightstep-tracer['"]/,            label: 'lightstep'            },
];

const PACKAGE_NAMES = new Set([
  '@opentelemetry/api', '@opentelemetry/sdk-node', '@opentelemetry/auto-instrumentations-node',
  '@segment/analytics-node', '@segment/analytics-next',
  'mixpanel', 'mixpanel-browser',
  'posthog-node', 'posthog-js',
  '@amplitude/analytics-node', '@amplitude/analytics-browser',
  '@datadog/browser-rum', '@datadog/browser-logs', 'dd-trace', 'datadog-metrics',
  '@newrelic/native-metrics', 'newrelic',
  '@sentry/node', '@sentry/browser', '@sentry/react', '@sentry/nextjs',
  'applicationinsights',
  'plausible-tracker',
  '@fathom-analytics/sdk',
  'simple-analytics',
  'rollbar',
  '@bugsnag/js', '@bugsnag/node',
  'logrocket', 'logrocket-react',
  '@fullstory/browser',
  'react-ga', 'react-ga4',
  'raygun4node',
  '@honeycombio/opentelemetry-node',
  'lightstep-tracer',
  'heap-api',
]);

module.exports = { SOURCE_PATTERNS, PACKAGE_NAMES };
