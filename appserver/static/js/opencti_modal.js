define([
  'underscore',
  'jquery',
  'app/SA-OpenCTIThreatMatch/js/opencti_saved_search',
  '/static/app/TA-virustotal-app/js/components/vt-toast.9ac17a3e.js',
], function(_, $, configApi) {

  class Modal {
    constructor(options) {
      const defaults = {
        title: 'Modal Title',
        destroyOnHide: true,
        width: null,
      };

      const modalOptions = _.extend(defaults, options || {});
      this.options = modalOptions;

      this.$el = $('<div>')
        .addClass('modal fade')
        .addClass('opencti-modal-wide')
        .attr({ role: 'dialog', tabindex: '-1' });

      if (modalOptions.width) {
        this.$el.css({ width: modalOptions.width });
      }

      const content = $('<div>').addClass('modal-content');
      const header = $('<div>').addClass('modal-header');
      const headerCloseButton = $('<button>')
        .addClass('close')
        .attr({
          type: 'button',
          'data-dismiss': 'modal',
          'aria-label': 'Close',
        })
        .append($('<span>').text('×'));

      const title = $('<h3>')
        .addClass('modal-title')
        .text(modalOptions.title);

      this.body = $('<div>')
        .addClass('modal-body')
        .css({
          'max-height': '70vh',
          'overflow-y': 'auto',
        });
      this.footer = $('<div>').addClass('modal-footer');

      content.append(header.append(headerCloseButton, title), this.body, this.footer);
      this.$el.append(content);

      if (modalOptions.destroyOnHide) {
        this.$el.on('hidden.bs.modal', function() {
          $(this).remove();
        });
      }

      $('body').append(this.$el);
      this.$el.modal({ show: false });
    }

    show() {
      this.$el.modal('show');
    }

    hide() {
      this.$el.modal('hide');
    }
  }

  class ModalDoc extends Modal {
    constructor(options) {
      super(options);
      $.get(options.docUrl, html => {
        this.body.append(html);
      });
    }
  }

  class ModalForm extends Modal {
    constructor(options) {
      super(options || {});
      this.options = options || {};
      this.form = this.createForm(this.options.searchName || null);
      this.body.append(this.form);

      let buttonLabel = this.options.searchName ? 'Edit' : 'Create';

      this.submitButton = $('<button>')
        .addClass('btn btn-primary')
        .attr('type', 'submit')
        .text(buttonLabel)
        .on('click', () => {
          this.form.trigger('submit');
        });

      this.form.on('submit', async event => {
        try {
          this.validateForm(this.form);
          event.preventDefault();

          if (!this.form[0].checkValidity()) {
            this.form[0].reportValidity();
            return;
          }

          this.submitButton.prop('disabled', true).text('Working...');

          if (this.options.searchName) {
            await this.submitEditForm(this.options.searchName);
            showToast('Correlation updated correctly', 'success');
          } else {
            await this.submitCreateForm();
            showToast('Correlation created correctly', 'success');
          }

          this.hide();
          if (this.options.onSave) {
            this.options.onSave();
          }
        } catch (err) {
          console.error('Error submitting correlation:', err);
          alert('Error submitting correlation. See browser console for details.');
        } finally {
          this.submitButton.prop('disabled', false).text(buttonLabel);
        }
      });

      this.footer.append(this.submitButton);

      if (this.options.searchName) {
        this.populateModalFields(this.options.searchName);
      }
    }

    // Abstracts
    createForm() {
      throw new Error('createForm must be implemented');
    }

    getFormData() {
      throw new Error('getFormData must be implemented');
    }

    buildMetadata() {
      throw new Error('buildMetadata must be implemented');
    }

    async populateModalFields() {
      throw new Error('populateModalFields must be implemented');
    }

    async submitCreateForm() {
      const formData = this.getFormData();
      const payload = this.buildMetadata(formData);
      await configApi.saveCorrelation(payload);
    }

    async submitEditForm(searchName) {
      const formData = this.getFormData();
      const payload = this.buildMetadata(formData);
      await configApi.updateCorrelation(searchName, payload);
    }

    validateForm() {
      throw new Error('validateForm must be implemented');
    }
  }

  class ModalCorrelationBasic extends ModalForm {
    constructor(options) {
      super(options || {});
    }

    validateForm() {
      function validateList(listString) {
        if (listString === '') {
          return false;
        }
        if (listString.trim() === '') {
          return false;
        }
        const pattern = /^[\w\.\-]+(?:,\s*[\w\.\-]+)*$/;
        return pattern.test(listString);
      }

      if (!validateList($('#openctiCorrelationIndexes').val())) {
        $('#openctiCorrelationIndexes')[0].setCustomValidity(
          'Comma-separated index list is not correctly formatted'
        );
      } else {
        $('#openctiCorrelationIndexes')[0].setCustomValidity('');
      }

      if (!validateList($('#openctiCorrelationFields').val())) {
        $('#openctiCorrelationFields')[0].setCustomValidity(
          'Comma-separated field list is not correctly formatted'
        );
      } else {
        $('#openctiCorrelationFields')[0].setCustomValidity('');
      }
    }

    createForm(searchName) {
      const form = $('<form>');

      if (searchName) {
        form
          .append($('<label>').addClass('opencti-modal-label').text('Name*'))
          .append(
            $('<input>').attr({
              type: 'text',
              id: 'openctiCorrelationNameDisplay',
              name: 'openctiCorrelationNameDisplay',
              class: 'form-control',
              required: true,
              readonly: true,
            })
          )
          .append(
            $('<input>').attr({
              type: 'hidden',
              id: 'openctiCorrelationName',
              name: 'openctiCorrelationName',
            })
          );
      } else {
        form
          .append($('<label>').addClass('opencti-modal-label').text('Name*'))
          .append(
            $('<input>').attr({
              type: 'text',
              id: 'openctiCorrelationName',
              name: 'openctiCorrelationName',
              class: 'form-control',
              required: true,
            })
          );
      }

      form
        .append($('<label>').addClass('opencti-modal-label').text('Description'))
        .append(
          $('<textarea>').attr({
            id: 'openctiCorrelationDescription',
            name: 'openctiCorrelationDescription',
            class: 'form-control',
          })
        );

      const iocTypeSelect = $('<select>').attr({
        id: 'openctiIocType',
        name: 'openctiIocType',
        class: 'form-control',
        required: true,
      });

      const iocTypes = [
        { value: 'url', text: 'URL' },
        { value: 'hash', text: 'Hash' },
        { value: 'domain', text: 'Domain' },
        { value: 'ip', text: 'IP' },
        { value: 'email', text: 'Email' },
      ];

      iocTypes.forEach(type => {
        iocTypeSelect.append(
          $('<option>').val(type.value).text(type.text)
        );
      });

      form.append($('<label>').addClass('opencti-modal-label').text('IOC Type*')).append(iocTypeSelect);

      // Show indexes above fields for better flow
      form
        .append($('<label>').addClass('opencti-modal-label').text('List of Indexes*'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiCorrelationIndexes',
            name: 'openctiCorrelationIndexes',
            class: 'form-control',
            required: true,
            placeholder: 'index1,index2,index3',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Enter a comma-separated list of index names (no spaces, no wildcards like index=*).'
          )
        );

      form
        .append($('<label>').addClass('opencti-modal-label').text('List of Fields*'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiCorrelationFields',
            name: 'openctiCorrelationFields',
            class: 'form-control',
            required: true,
            placeholder: 'field1,field2,field3',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Enter a comma-separated list of field names to search (no spaces between commas).'
          )
        );

      form
        .append($('<label>').addClass('opencti-modal-label').text('Exclude text (optional)'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiCorrelationExcludeText',
            name: 'openctiCorrelationExcludeText',
            class: 'form-control',
            placeholder: 'text1,text2 (e.g. blocked,internal)',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Comma-separated simple text values to exclude (no spaces between commas). Events where the target fields contain any of these values will be excluded before matching. Matching is case-sensitive, and most IOC candidates are normalized to lowercase, so enter exclude text in lowercase.'
          )
        );

      form
        .append($('<label>').addClass('opencti-modal-label').text('Exclude regex (optional)'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiCorrelationExcludeRegex',
            name: 'openctiCorrelationExcludeRegex',
            class: 'form-control',
            placeholder: 'regex1,regex2 (advanced)',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Comma-separated regex patterns to exclude events (advanced). Use text exclude above for simple cases.'
          )
        );

      form.append($('<hr>'));
      form.append(
        $('<p class="input-description">').text(
          'This correlation will be executed every 5 minutes over the last 5 minutes of indexed data.'
        )
      );

      return form;
    }

    async populateModalFields(searchName) {
      try {
        this.submitButton.prop('disabled', true).text('Loading...');
        const data = await configApi.getCorrelation(searchName);
        $('#openctiCorrelationName').val(data._key).prop('disabled', true);
        $('#openctiCorrelationNameDisplay')
          .val(data._key)
          .prop('disabled', true);
        $('#openctiCorrelationDescription').val(data.description || '');
        $('#openctiIocType').val(data.ioc_type || '');
        $('#openctiCorrelationFields').val(data.fields || '');
        $('#openctiCorrelationIndexes').val(data.indexes || '');
        $('#openctiCorrelationExcludeText').val(data.exclude_text || '');
        $('#openctiCorrelationExcludeRegex').val(data.exclude_regex || '');
      } catch (err) {
        console.error('Error fetching saved search:', err);
      } finally {
        this.submitButton.prop('disabled', false).text('Edit');
      }
    }

    getFormData() {
      return {
        correlationName: $('#openctiCorrelationName').val().trim(),
        correlationDescription: $('#openctiCorrelationDescription').val().trim(),
        iocType: $('#openctiIocType').val(),
        correlationFields: $('#openctiCorrelationFields').val(),
        correlationIndexes: $('#openctiCorrelationIndexes').val(),
        excludeText: $('#openctiCorrelationExcludeText').val(),
        excludeRegex: $('#openctiCorrelationExcludeRegex').val(),
      };
    }

    buildMetadata(formData) {
      return {
        name: formData.correlationName,
        description: formData.correlationDescription,
        ioc_type: formData.iocType,
        indexes: formData.correlationIndexes,
        fields: formData.correlationFields,
        enabled: 1,
        correlation_mode: 'basic',
        exclude_text: formData.excludeText,
        regex_pattern: '',
        exclude_regex: formData.excludeRegex,
      };
    }
  }

  class ModalCorrelationRegex extends ModalForm {
    constructor(options) {
      super(options || {});
    }

    validateForm() {
      function validateList(listString) {
        if (listString === '') {
          return false;
        }
        if (listString.trim() === '') {
          return false;
        }
        const pattern = /^[\w\.\-]+(?:,\s*[\w\.\-]+)*$/;
        return pattern.test(listString);
      }

      if (!validateList($('#openctiRegexIndexes').val())) {
        $('#openctiRegexIndexes')[0].setCustomValidity(
          'Comma-separated index list is not correctly formatted'
        );
      } else {
        $('#openctiRegexIndexes')[0].setCustomValidity('');
      }

      if (!validateList($('#openctiRegexFields').val())) {
        $('#openctiRegexFields')[0].setCustomValidity(
          'Comma-separated field list is not correctly formatted'
        );
      } else {
        $('#openctiRegexFields')[0].setCustomValidity('');
      }

      if (!$('#openctiRegexPattern').val()) {
        $('#openctiRegexPattern')[0].setCustomValidity('Regex pattern is required');
      } else {
        $('#openctiRegexPattern')[0].setCustomValidity('');
      }
    }

    createForm(searchName) {
      const form = $('<form>');

      if (searchName) {
        form
          .append($('<label>').addClass('opencti-modal-label').text('Name*'))
          .append(
            $('<input>').attr({
              type: 'text',
              id: 'openctiRegexNameDisplay',
              name: 'openctiRegexNameDisplay',
              class: 'form-control',
              required: true,
              readonly: true,
            })
          )
          .append(
            $('<input>').attr({
              type: 'hidden',
              id: 'openctiRegexName',
              name: 'openctiRegexName',
            })
          );
      } else {
        form
          .append($('<label>').addClass('opencti-modal-label').text('Name*'))
          .append(
            $('<input>').attr({
              type: 'text',
              id: 'openctiRegexName',
              name: 'openctiRegexName',
              class: 'form-control',
              required: true,
            })
          );
      }

      form
        .append($('<label>').addClass('opencti-modal-label').text('Description'))
        .append(
          $('<textarea>').attr({
            id: 'openctiRegexDescription',
            name: 'openctiRegexDescription',
            class: 'form-control',
          })
        );

      const iocTypeSelect = $('<select>').attr({
        id: 'openctiRegexIocType',
        name: 'openctiRegexIocType',
        class: 'form-control',
        required: true,
      });

      const iocTypes = [
        { value: 'ip', text: 'IP' },
        { value: 'domain', text: 'Domain' },
        { value: 'url', text: 'URL' },
        { value: 'hash', text: 'Hash' },
        { value: 'email', text: 'Email' },
      ];

      iocTypes.forEach(type => {
        iocTypeSelect.append(
          $('<option>').val(type.value).text(type.text)
        );
      });

      form.append($('<label>').addClass('opencti-modal-label').text('IOC Type*')).append(iocTypeSelect);

      form
        .append($('<label>').addClass('opencti-modal-label').text('List of Indexes*'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiRegexIndexes',
            name: 'openctiRegexIndexes',
            class: 'form-control',
            required: true,
            placeholder: 'index1,index2,index3',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Comma-separated indexes to search (no spaces, no wildcards like index=*).'
          )
        );

      form
        .append($('<label>').addClass('opencti-modal-label').text('List of Fields*'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiRegexFields',
            name: 'openctiRegexFields',
            class: 'form-control',
            required: true,
            placeholder: 'field1,field2,field3',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Comma-separated text fields to run the regex over (no spaces between commas).'
          )
        );

      form
        .append($('<label>').addClass('opencti-modal-label').text('IOC Extraction Regex*'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiRegexPattern',
            name: 'openctiRegexPattern',
            class: 'form-control',
            required: true,
            placeholder: 'Enter regex to extract IOCs',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Regex used to extract IOC candidates from the selected fields.'
          )
        );

      const suggestionsList = $('<ul class="input-description">')
        .append(
          $('<li>').html(
            'Domain: <code>[A-Za-z0-9.-]+\\.[A-Za-z]{2,}</code>'
          )
        )
        .append(
          $('<li>').html(
            'URL (full value): <code>^https?://.+</code>'
          )
        )
        .append(
          $('<li>').html(
            'Hash (md5/sha1/sha256): <code>(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})</code>'
          )
        )
        .append(
          $('<li>').html(
            'Email: <code>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}</code>'
          )
        )
        .append(
          $('<li>').html(
            'IPv4 (single IPs in events, e.g. 10.0.0.1): <code>[0-9]{1,3}(?:\\.[0-9]{1,3}){3}</code>'
          )
        )
        .append(
          $('<li>').html(
            'IPv4 CIDR (only if your events literally contain ranges like 203.0.113.0/24): <code>[0-9]{1,3}(?:\\.[0-9]{1,3}){3}/[0-9]{1,2}</code>'
          )
        )
        .append(
          $('<li>').html(
            'IPv6: <code>[0-9A-Fa-f:]+</code>'
          )
        )
        .append(
          $('<li>').html(
            'IPv6 CIDR: <code>[0-9A-Fa-f:]+/[0-9]{1,3}</code>'
          )
        );

      form.append(
        $('<p class="input-description">').text(
          'Suggested patterns (taken from the OpenCTI KV builders; you can adjust anchors ^ and $ as needed for extraction):'
        )
      );
      form.append(suggestionsList);

      form
        .append($('<label>').addClass('opencti-modal-label').text('Exclude text (optional)'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiRegexExcludeText',
            name: 'openctiRegexExcludeText',
            class: 'form-control',
            placeholder: 'text1,text2 (e.g. blocked,internal)',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Comma-separated simple text values to exclude (no spaces between commas). Events where the target field(s) contain any of these values will be excluded before IOC extraction. Matching is case-sensitive, and most IOC candidates are normalized to lowercase, so enter exclude text in lowercase.'
          )
        );

      form
        .append($('<label>').addClass('opencti-modal-label').text('Exclude regex (optional)'))
        .append(
          $('<input>').attr({
            type: 'text',
            id: 'openctiRegexExcludeRegex',
            name: 'openctiRegexExcludeRegex',
            class: 'form-control',
            placeholder: 'regex1,regex2 (advanced)',
          })
        )
        .append(
          $('<p class="input-description">').text(
            'Comma-separated regex patterns to exclude events (advanced). Use text exclude above for simple cases.'
          )
        );

      form.append($('<hr>'));
      form.append(
        $('<p class="input-description">').text(
          'Regex correlations reuse the same 5-minute Threat Match window and summary index as basic correlations.'
        )
      );

      return form;
    }

    async populateModalFields(searchName) {
      try {
        this.submitButton.prop('disabled', true).text('Loading...');
        const data = await configApi.getCorrelation(searchName);
        $('#openctiRegexName').val(data._key).prop('disabled', true);
        $('#openctiRegexNameDisplay')
          .val(data._key)
          .prop('disabled', true);
        $('#openctiRegexDescription').val(data.description || '');
        $('#openctiRegexIocType').val(data.ioc_type || '');
        $('#openctiRegexIndexes').val(data.indexes || '');
        $('#openctiRegexFields').val(data.fields || '');
        $('#openctiRegexPattern').val(data.regex_pattern || '');
        $('#openctiRegexExcludeText').val(data.exclude_text || '');
        $('#openctiRegexExcludeRegex').val(data.exclude_regex || '');
      } catch (err) {
        console.error('Error fetching regex correlation:', err);
      } finally {
        this.submitButton.prop('disabled', false).text('Edit');
      }
    }

    getFormData() {
      return {
        correlationName: $('#openctiRegexName').val().trim(),
        correlationDescription: $('#openctiRegexDescription').val().trim(),
        iocType: $('#openctiRegexIocType').val(),
        correlationIndexes: $('#openctiRegexIndexes').val(),
        correlationFields: $('#openctiRegexFields').val(),
        regexPattern: $('#openctiRegexPattern').val(),
        excludeText: $('#openctiRegexExcludeText').val(),
        excludeRegex: $('#openctiRegexExcludeRegex').val(),
      };
    }

    buildMetadata(formData) {
      return {
        name: formData.correlationName,
        description: formData.correlationDescription,
        ioc_type: formData.iocType,
        indexes: formData.correlationIndexes,
        fields: formData.correlationFields,
        enabled: 1,
        correlation_mode: 'regex',
        exclude_text: formData.excludeText,
        regex_pattern: formData.regexPattern,
        exclude_regex: formData.excludeRegex,
      };
    }
  }

  return {
    Modal: Modal,
    ModalForm: ModalForm,
    ModalDoc: ModalDoc,
    ModalCorrelationBasic: ModalCorrelationBasic,
    ModalCorrelationRegex: ModalCorrelationRegex,
  };
});
