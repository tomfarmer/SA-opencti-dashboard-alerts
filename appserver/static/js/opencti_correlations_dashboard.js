require([
  'underscore',
  'jquery',
  'app/SA-opencti-dashboard-alerts/js/opencti_saved_search',
  'app/SA-opencti-dashboard-alerts/js/opencti_modal',
  '/static/app/TA-virustotal-app/js/components/vt-toast.js',
  'splunkjs/mvc/simplexml/ready!',
], function(_, $, configApi, openctiModal) {

  function TableController($table, rows) {
    const pageSize = 10;
    let currentPage = 1;

    let $pagination = $table.parent().parent().find('.pagination');
    if ($pagination.length === 0) {
      $pagination = $('<div class="pagination"></div>');
      $table.parent().after($pagination);
    }

    function showPage(page) {
      const startIndex = (page - 1) * pageSize;
      const endIndex = startIndex + pageSize;
      const pageRows = rows.slice(startIndex, endIndex);
      $table.empty();
      $table.append(pageRows);
    }

    function updatePagination() {
      const numPages = Math.ceil(rows.length / pageSize) || 1;
      $pagination.empty();

      const prevButton = $('<button class="btn btn-secondary">&laquo; Previous</button>');
      if (currentPage === 1) {
        prevButton.prop('disabled', true);
      } else {
        prevButton.on('click', function() {
          currentPage--;
          showPage(currentPage);
          updatePagination();
        });
      }
      $pagination.append(prevButton);

      for (let i = 1; i <= numPages; i++) {
        const pageButton = $('<button class="btn btn-secondary"></button>').text(i);
        if (i === currentPage) {
          pageButton.addClass('active');
        } else {
          pageButton.on('click', function() {
            currentPage = i;
            showPage(currentPage);
            updatePagination();
          });
        }
        $pagination.append(pageButton);
      }

      const nextButton = $('<button class="btn btn-secondary">Next &raquo;</button>');
      if (currentPage === numPages) {
        nextButton.prop('disabled', true);
      } else {
        nextButton.on('click', function() {
          currentPage++;
          showPage(currentPage);
          updatePagination();
        });
      }
      $pagination.append(nextButton);
    }

    showPage(currentPage);
    updatePagination();
  }

  function buildRow(correlation, isRegex) {
    const name = correlation._key || correlation.name || '';
    const description = correlation.description || '';
    const indexList = correlation.indexes || '';
    const fieldList = correlation.fields || '';
    const lastRun = correlation.last_run || '';
    const enabled = correlation.enabled === 1 || correlation.enabled === true;

    const $row = $('<tr></tr>');
    $row.append('<th scope="row"></th>');

    const $enableCell = $('<td></td>');
    const $switchLabel = $('<label class="switch"></label>');
    const $checkbox = $('<input type="checkbox" class="enable-checkbox">').attr(
      'data-search-name',
      name
    );
    if (enabled) {
      $checkbox.prop('checked', true);
    }
    const $slider = $('<span class="slider round"></span>');
    $switchLabel.append($checkbox, $slider);
    $enableCell.append($switchLabel);
    $row.append($enableCell);

    $row.append($('<td></td>').text(name));
    $row.append($('<td></td>').text(description));
    if (isRegex) {
      $row.append($('<td></td>').text(correlation.ioc_type || ''));
      $row.append($('<td></td>').text(indexList));
      $row.append($('<td></td>').text(fieldList));
      $row.append($('<td></td>').text(correlation.regex_pattern || ''));
    } else {
      $row.append($('<td></td>').text(indexList));
      $row.append($('<td></td>').text(fieldList));
      $row.append($('<td></td>').text(lastRun));
    }

    const $actions = $('<td></td>');
    const $deleteButton = $('<button class="btn btn-danger btn-sm delete-button">Delete</button>')
      .attr('data-search-name', name);
    const $editButton = $('<button class="btn btn-danger btn-sm edit-button">Edit</button>')
      .attr('data-search-name', name)
      .attr('data-mode', correlation.correlation_mode || 'basic');
    $actions.append($deleteButton, ' ', $editButton);
    $row.append($actions);

    return $row;
  }

  async function populateTable() {
    const $tableBasic = $('.js-opencti-correlations-table-basic');
    const $tableRegex = $('.js-opencti-correlations-table-regex');
    const loading = $('<div class="loading"><span>Loading...</span></div>');
    const $tabContent = $('.tab-content');
    $tabContent.before(loading);

    let correlations = [];
    try {
      correlations = await configApi.listCorrelations();
    } catch (err) {
      console.error('Error fetching OpenCTI correlations:', err);
      showToast('Error loading correlations. Check JS console for details.', 'error');
      loading.remove();
      return;
    }

    correlations.sort(function(a, b) {
      return (a._key || '').localeCompare(b._key || '');
    });

    loading.remove();

    const basicRows = [];
    const regexRows = [];
    correlations.forEach(function(c) {
      const mode = c.correlation_mode || 'basic';
      if (mode === 'regex') {
        regexRows.push(buildRow(c, true));
      } else {
        basicRows.push(buildRow(c, false));
      }
    });

    TableController($tableBasic, basicRows);
    TableController($tableRegex, regexRows);
  }

  async function updateTable() {
    const $tableBasic = $('.js-opencti-correlations-table-basic');
    const $tableRegex = $('.js-opencti-correlations-table-regex');
    $tableBasic.empty();
    $tableRegex.empty();
    await populateTable();
  }

  const tablesSelector = '.js-opencti-correlations-table-basic, .js-opencti-correlations-table-regex';

  $(tablesSelector).on('click', '.delete-button', async function() {
    const name = $(this).data('search-name');
    if (!name) {
      return;
    }
    if (!confirm('Are you sure you want to delete the correlation "' + name + '"?')) {
      return;
    }
    try {
      await configApi.deleteCorrelation(name);
      showToast('Correlation "' + name + '" deleted.', 'success');
    } catch (err) {
      console.error('Error deleting correlation:', err);
      showToast('Error deleting correlation. See JS console.', 'error');
    }
    updateTable();
  });

  $(tablesSelector).on('click', '.edit-button', async function() {
    const searchName = $(this).data('search-name');
    const modeAttr = $(this).data('mode');
    const mode = modeAttr || 'basic';
    let modal;
    if (mode === 'regex') {
      modal = new openctiModal.ModalCorrelationRegex({
        title: 'Edit Regex Correlation Search',
        searchName: searchName,
        onSave: updateTable,
      });
    } else {
      modal = new openctiModal.ModalCorrelationBasic({
        title: 'Edit Correlation Search',
        searchName: searchName,
        onSave: updateTable,
      });
    }
    modal.show();
  });

  $(tablesSelector).on('change', '.enable-checkbox', async function() {
    const name = $(this).data('search-name');
    const isEnabled = $(this).prop('checked');
    try {
      await configApi.setEnabled(name, isEnabled);
      const message = isEnabled
        ? 'Correlation "' + name + '" enabled.'
        : 'Correlation "' + name + '" disabled.';
      showToast(message, 'info');
    } catch (err) {
      console.error('Error toggling correlation:', err);
      showToast('Error updating correlation state.', 'error');
    }
  });

  $('#addOpenCtiBasicCorrelation').on('click', function() {
    const modal = new openctiModal.ModalCorrelationBasic({
      title: 'New Basic Correlation Search',
      onSave: updateTable,
    });
    modal.show();
  });

  $('#addOpenCtiRegexCorrelation').on('click', function() {
    const modal = new openctiModal.ModalCorrelationRegex({
      title: 'New Regex Correlation Search',
      onSave: updateTable,
    });
    modal.show();
  });

  $('#openctiDocButton').on('click', function() {
    const docModal = new openctiModal.ModalDoc({
      title: 'OpenCTI Correlations Dashboard Documentation',
      docUrl: '/static/app/SA-opencti-dashboard-alerts/html/opencti_sources_doc.html',
    });
    docModal.show();
  });

  populateTable();
});
