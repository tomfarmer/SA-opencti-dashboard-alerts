define([
  'jquery',
  'splunk.util',
  'splunkjs/mvc',
], function($, splunkUtil, mvc) {

  // Base REST path for the KV collection. Use /servicesNS with explicit app
  // so we hit the correct namespace from Splunk Web.
  const COLLECTION_REST_PATH = '/servicesNS/nobody/SA-OpenCTIThreatMatch/storage/collections/data/opencti_tm_monitored_indexs_and_fields';
  // For raw AJAX calls, include the splunkd/__raw prefix explicitly.
  const COLLECTION_URL = splunkUtil.make_url('/splunkd/__raw' + COLLECTION_REST_PATH);

  function createService() {
    return mvc.createService({ owner: 'nobody' });
  }

  function ajaxJson(method, url, payload) {
    return $.ajax({
      type: method,
      url: url,
      contentType: 'application/json',
      dataType: 'json',
      data: payload ? JSON.stringify(payload) : null,
    });
  }

  function normalizeList(raw) {
    if (!raw) {
      return '';
    }
    return raw
      .split(',')
      .map(function(item) { return item.trim(); })
      .filter(function(item) { return item.length > 0; })
      .join(',');
  }

  function hasWildcardIndex(raw) {
    if (!raw) {
      return false;
    }
    return raw.split(',').some(function(item) {
      return item.trim() === '*' || item.indexOf('*') !== -1;
    });
  }

  async function getCurrentUser(service) {
    try {
      const respRaw = await service.get('/services/authentication/current-context', {
        output_mode: 'json',
      });
      const resp = typeof respRaw === 'string' ? JSON.parse(respRaw) : respRaw;
      const entry = resp.entry && resp.entry[0];
      if (entry && entry.content && entry.content.username) {
        return entry.content.username;
      }
    } catch (e) {
      // ignore
    }
    return null;
  }

  async function listCorrelations() {
    const service = createService();
    const respRaw = await service.get(COLLECTION_REST_PATH, { output_mode: 'json' });
    const resp = typeof respRaw === 'string' ? JSON.parse(respRaw) : respRaw;
    return resp || [];
  }

  async function getCorrelation(name) {
    const service = createService();
    const respRaw = await service.get(
      COLLECTION_REST_PATH + '/' + encodeURIComponent(name),
      { output_mode: 'json' }
    );
    const resp = typeof respRaw === 'string' ? JSON.parse(respRaw) : respRaw;
    return resp;
  }

  async function saveCorrelation(data) {
    const indexes = normalizeList(data.indexes);
    const fields = normalizeList(data.fields);
    const excludeText = normalizeList(data.exclude_text);
    const excludeRegex = normalizeList(data.exclude_regex);

    if (!indexes || !fields) {
      throw new Error('Indexes and fields are required');
    }
    if (hasWildcardIndex(indexes)) {
      throw new Error('index=* or wildcard indexes are not allowed');
    }

    const service = createService();

    const now = Date.now();
    const user = await getCurrentUser(service);
    const mode = data.correlation_mode || 'basic';

    const payload = {
      _key: data.name,
      description: data.description || '',
      ioc_type: data.ioc_type,
      indexes: indexes,
      fields: fields,
      enabled: data.enabled ? 1 : 0,
      last_updated: now,
      correlation_mode: mode,
      exclude_text: excludeText || '',
      regex_pattern: data.regex_pattern || '',
      exclude_regex: excludeRegex || '',
    };
    if (user && !data.created_by) {
      payload.created_by = user;
    } else if (data.created_by) {
      payload.created_by = data.created_by;
    }

    // Use a raw JSON POST so Splunkd sees Content-Type: application/json.
    await ajaxJson('POST', COLLECTION_URL, payload);
  }

  async function updateCorrelation(name, data) {
    const indexes = normalizeList(data.indexes);
    const fields = normalizeList(data.fields);
    const excludeText = normalizeList(data.exclude_text);
    const excludeRegex = normalizeList(data.exclude_regex);

    if (!indexes || !fields) {
      throw new Error('Indexes and fields are required');
    }
    if (hasWildcardIndex(indexes)) {
      throw new Error('index=* or wildcard indexes are not allowed');
    }

    const service = createService();

    const now = Date.now();
    const mode = data.correlation_mode || 'basic';

    const payload = {
      description: data.description || '',
      ioc_type: data.ioc_type,
      indexes: indexes,
      fields: fields,
      enabled: data.enabled ? 1 : 0,
      last_updated: now,
      correlation_mode: mode,
      exclude_text: excludeText || '',
      regex_pattern: data.regex_pattern || '',
      exclude_regex: excludeRegex || '',
    };

    await ajaxJson(
      'POST',
      COLLECTION_URL + '/' + encodeURIComponent(name),
      payload
    );
  }

  async function deleteCorrelation(name) {
    const service = createService();
    await service.del(COLLECTION_REST_PATH + '/' + encodeURIComponent(name));
  }

  async function setEnabled(name, enabled) {
    const service = createService();
    const payload = {
      enabled: enabled ? 1 : 0,
      last_updated: Date.now(),
    };
    await ajaxJson(
      'POST',
      COLLECTION_URL + '/' + encodeURIComponent(name),
      payload
    );
  }

  return {
    listCorrelations: listCorrelations,
    getCorrelation: getCorrelation,
    saveCorrelation: saveCorrelation,
    updateCorrelation: updateCorrelation,
    deleteCorrelation: deleteCorrelation,
    setEnabled: setEnabled,
  };
});
