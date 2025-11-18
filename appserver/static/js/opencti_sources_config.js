require([
  'jquery',
  'underscore',
  'splunkjs/mvc',
  'splunkjs/mvc/simplexml/ready!',
], function($, _, mvc) {

  const MACRO_ROWS = [
    {
      key: 'domains',
      label: 'Domains',
      macro: 'domains_event_sources',
      notes: 'DNS events (for domain matches).',
    },
    {
      key: 'ip',
      label: 'IP addresses',
      macro: 'ip_event_sources',
      notes: 'Flow / network telemetry for IP matches.',
    },
    {
      key: 'url',
      label: 'URLs',
      macro: 'url_event_sources',
      notes: 'HTTP / proxy events for URL matches.',
    },
    {
      key: 'file',
      label: 'Files',
      macro: 'files_event_sources',
      notes: 'File events (hash / object logs).',
    },
    {
      key: 'email',
      label: 'Emails',
      macro: 'email_event_sources',
      notes: 'SMTP / email telemetry for email matches.',
    },
  ];

  function createService() {
    return mvc.createService({ owner: 'nobody' });
  }

  function extractIndexesFromMacro(definition) {
    if (!definition) {
      return '';
    }

    const trimmed = definition.trim();
    if (!trimmed) {
      return '';
    }

    const withoutParens =
      trimmed.startsWith('(') && trimmed.endsWith(')')
        ? trimmed.slice(1, -1)
        : trimmed;

    const parts = withoutParens.split(/\s+OR\s+/i);

    const indices = parts
      .map(function(part) {
        const match = part.match(/index\s*=\s*("?)([^"\s]+)\1/i);
        return match ? match[2] : null;
      })
      .filter(function(v) {
        return v;
      });

    return indices.join(',');
  }

  function buildMacroDefinitionFromIndexes(indexList) {
    if (!indexList) {
      return '';
    }

    const indices = indexList
      .split(',')
      .map(function(idx) {
        return idx.trim();
      })
      .filter(function(idx) {
        return idx.length > 0;
      });

    if (indices.length === 0) {
      return '';
    }

    const parts = indices.map(function(idx) {
      return 'index=' + idx;
    });

    return '(' + parts.join(' OR ') + ')';
  }

  async function loadMacroDefinition(service, macroName) {
    try {
      const definition = await service.get(
        '/services/properties/macros/' + encodeURIComponent(macroName) + '/definition'
      );
      return typeof definition === 'string' ? definition : (definition || '').toString();
    } catch (e) {
      console.error('Error loading macro definition for', macroName, e);
      throw e;
    }
  }

  async function saveMacroDefinition(service, macroName, definition) {
    try {
      await service.post(
        '/services/properties/macros/' + encodeURIComponent(macroName) + '/definition',
        { value: definition }
      );
    } catch (e) {
      console.error('Error saving macro definition for', macroName, e);
      throw e;
    }
  }

  function renderRow(rowConfig, indexList) {
    const safeKey = _.escape(rowConfig.key);
    const macroName = _.escape(rowConfig.macro);
    const label = _.escape(rowConfig.label);
    const notes = _.escape(rowConfig.notes);
    const value = _.escape(indexList || '');

    return (
      '<tr data-key="' + safeKey + '" data-macro="' + macroName + '">' +
        '<td>' + label + '</td>' +
        '<td><code>`' + macroName + '`</code></td>' +
        '<td>' +
          '<input type="text" class="form-control opencti-config-index-input js-index-input" ' +
          'value="' + value + '" placeholder="index1,index2,..." />' +
          '<div class="opencti-config-status js-status"></div>' +
        '</td>' +
        '<td>' + notes + '</td>' +
        '<td>' +
          '<button type="button" class="btn btn-primary btn-sm js-save">Save</button> ' +
          '<button type="button" class="btn btn-default btn-sm js-reset">Reset</button>' +
        '</td>' +
      '</tr>'
    );
  }

  async function populateTable() {
    const service = createService();
    const tbody = $('#opencti-sources-table');
    tbody.empty();

    for (let i = 0; i < MACRO_ROWS.length; i++) {
      const rowConfig = MACRO_ROWS[i];
      let indexList = '';

      try {
        const definition = await loadMacroDefinition(service, rowConfig.macro);
        indexList = extractIndexesFromMacro(definition);
      } catch (e) {
        indexList = '';
      }

      const rowHtml = renderRow(rowConfig, indexList);
      tbody.append(rowHtml);
    }
  }

  function attachHandlers() {
    $('#opencti-sources-table').on('click', '.js-save', async function() {
      const row = $(this).closest('tr');
      const macroName = row.data('macro');
      const input = row.find('.js-index-input');
      const status = row.find('.js-status');
      const rawValue = input.val();

      status
        .removeClass('ok error')
        .text('Saving...');

      const definition = buildMacroDefinitionFromIndexes(rawValue);
      const service = createService();

      try {
        await saveMacroDefinition(service, macroName, definition);
        status
          .addClass('ok')
          .removeClass('error')
          .text('Saved');
      } catch (e) {
        status
          .addClass('error')
          .removeClass('ok')
          .text('Error saving macro (see JS console).');
      }
    });

    $('#opencti-sources-table').on('click', '.js-reset', async function() {
      const row = $(this).closest('tr');
      const macroName = row.data('macro');
      const input = row.find('.js-index-input');
      const status = row.find('.js-status');
      const service = createService();

      status
        .removeClass('ok error')
        .text('Reloading...');

      try {
        const definition = await loadMacroDefinition(service, macroName);
        const indexList = extractIndexesFromMacro(definition);
        input.val(indexList);
        status
          .addClass('ok')
          .removeClass('error')
          .text('Reloaded');
      } catch (e) {
        status
          .addClass('error')
          .removeClass('ok')
          .text('Error reloading macro (see JS console).');
      }
    });

    $('#openctiDocButton').on('click', function() {
      window.open(
        '/static/app/SA-opencti-dashboard-alerts/html/opencti_sources_doc.html',
        '_blank'
      );
    });
  }

  (async function init() {
    await populateTable();
    attachHandlers();
  })();
});

