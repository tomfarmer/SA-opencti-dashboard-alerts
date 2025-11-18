define([
  'splunkjs/mvc',
], function(mvc) {

  const COLLECTION_PATH = '/services/storage/collections/data/opencti_tm_monitored_indexs_and_fields';

  function createService() {
    return mvc.createService({ owner: 'nobody' });
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
    const respRaw = await service.get(COLLECTION_PATH, { output_mode: 'json' });
    const resp = typeof respRaw === 'string' ? JSON.parse(respRaw) : respRaw;
    return resp || [];
  }

  async function getCorrelation(name) {
    const service = createService();
    const respRaw = await service.get(
      COLLECTION_PATH + '/' + encodeURIComponent(name),
      { output_mode: 'json' }
    );
    const resp = typeof respRaw === 'string' ? JSON.parse(respRaw) : respRaw;
    return resp;
  }

  async function saveCorrelation(data) {
    const service = createService();

    const indexes = normalizeList(data.indexes);
    const fields = normalizeList(data.fields);

    if (!indexes || !fields) {
      throw new Error('Indexes and fields are required');
    }
    if (hasWildcardIndex(indexes)) {
      throw new Error('index=* or wildcard indexes are not allowed');
    }

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
      regex_pattern: data.regex_pattern || '',
      exclude_regex: data.exclude_regex || '',
    };
    if (user && !data.created_by) {
      payload.created_by = user;
    } else if (data.created_by) {
      payload.created_by = data.created_by;
    }

    await service.post(COLLECTION_PATH, payload);
  }

  async function updateCorrelation(name, data) {
    const service = createService();

    const indexes = normalizeList(data.indexes);
    const fields = normalizeList(data.fields);

    if (!indexes || !fields) {
      throw new Error('Indexes and fields are required');
    }
    if (hasWildcardIndex(indexes)) {
      throw new Error('index=* or wildcard indexes are not allowed');
    }

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
      regex_pattern: data.regex_pattern || '',
      exclude_regex: data.exclude_regex || '',
    };

    await service.post(
      COLLECTION_PATH + '/' + encodeURIComponent(name),
      payload
    );
  }

  async function deleteCorrelation(name) {
    const service = createService();
    await service.del(COLLECTION_PATH + '/' + encodeURIComponent(name));
  }

  async function setEnabled(name, enabled) {
    const service = createService();
    const payload = {
      enabled: enabled ? 1 : 0,
      last_updated: Date.now(),
    };
    await service.post(
      COLLECTION_PATH + '/' + encodeURIComponent(name),
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
