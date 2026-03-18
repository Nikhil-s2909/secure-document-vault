/**
 * static/js/main.js
 * ------------------
 * Client-side interactivity for the Secure Document Vault UI.
 *
 * Modules
 * -------
 * 1. Drop-zone — drag-and-drop + click-to-browse file selection
 * 2. Upload form — enable submit button only when a valid file is chosen,
 *                  show progress state during submission
 * 3. Auto-dismiss alerts — fade out success messages after 4 s
 * 4. Confirm-delete guard — already handled inline via onsubmit, kept here
 *    as a fallback for dynamically inserted forms
 */

(function () {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* 1. Drop-zone                                                         */
  /* ------------------------------------------------------------------ */
  const dropZone     = document.getElementById('drop-zone');
  const fileInput    = document.getElementById('file-upload');
  const dropContent  = document.getElementById('drop-content');
  const fileSelected = document.getElementById('file-selected');
  const selectedName = document.getElementById('selected-name');
  const selectedSize = document.getElementById('selected-size');
  const clearBtn     = document.getElementById('clear-file');
  const uploadBtn    = document.getElementById('upload-btn');

  if (dropZone && fileInput) {

    /* Drag events */
    ['dragenter', 'dragover'].forEach(evt => {
      dropZone.addEventListener(evt, e => {
        e.preventDefault();
        dropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(evt => {
      dropZone.addEventListener(evt, e => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
      });
    });

    dropZone.addEventListener('drop', e => {
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        // Assign dropped file to the hidden input via DataTransfer
        const dt = new DataTransfer();
        dt.items.add(files[0]);
        fileInput.files = dt.files;
        showSelectedFile(files[0]);
      }
    });

    /* Regular input change (browse) */
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0) {
        showSelectedFile(fileInput.files[0]);
      }
    });

    /* Clear button */
    if (clearBtn) {
      clearBtn.addEventListener('click', e => {
        e.stopPropagation();
        fileInput.value = '';
        showDropZone();
      });
    }

    /**
     * Show the "file selected" panel and enable the upload button.
     * @param {File} file
     */
    function showSelectedFile(file) {
      if (dropContent)  dropContent.style.display  = 'none';
      if (fileSelected) fileSelected.style.display = 'flex';
      if (selectedName) selectedName.textContent   = file.name;
      if (selectedSize) selectedSize.textContent   = formatBytes(file.size);
      if (uploadBtn)    uploadBtn.disabled          = false;
    }

    /** Reset to the drop zone state and disable the upload button. */
    function showDropZone() {
      if (dropContent)  dropContent.style.display  = '';
      if (fileSelected) fileSelected.style.display = 'none';
      if (uploadBtn)    uploadBtn.disabled          = true;
    }
  }

  /* ------------------------------------------------------------------ */
  /* 2. Upload form — progress state on submit                           */
  /* ------------------------------------------------------------------ */
  const uploadForm = document.getElementById('upload-form');
  if (uploadForm && uploadBtn) {
    uploadForm.addEventListener('submit', () => {
      uploadBtn.disabled = true;
      const span = uploadBtn.querySelector('span');
      if (span) span.textContent = 'Encrypting & uploading…';
      uploadBtn.style.opacity = '0.7';
    });
  }

  /* ------------------------------------------------------------------ */
  /* 3. Auto-dismiss alerts                                              */
  /* ------------------------------------------------------------------ */
  document.querySelectorAll('.alert').forEach(alert => {
    setTimeout(() => {
      alert.style.transition = 'opacity 0.5s';
      alert.style.opacity    = '0';
      setTimeout(() => alert.remove(), 500);
    }, 5000);
  });

  /* ------------------------------------------------------------------ */
  /* 4. Confirm-delete fallback for dynamically inserted forms           */
  /* ------------------------------------------------------------------ */
  document.addEventListener('submit', e => {
    const form = e.target;
    if (form.matches('[data-confirm]')) {
      if (!confirm(form.dataset.confirm)) {
        e.preventDefault();
      }
    }
  });

  /* ------------------------------------------------------------------ */
  /* Helpers                                                              */
  /* ------------------------------------------------------------------ */

  /**
   * Convert bytes to a human-readable string (matches Python helper in views).
   * @param {number} bytes
   * @returns {string}
   */
  function formatBytes(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) {
      bytes /= 1024;
      i++;
    }
    return `${bytes.toFixed(1)} ${units[i]}`;
  }

})();
