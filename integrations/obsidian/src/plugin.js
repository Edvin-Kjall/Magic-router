// Obsidian plugin: "Seal link" command — seals the selection (or a pasted
// URL) with a password and copies the sealed link to the clipboard.
// Bundled with esbuild (see esbuild.config.js) into a single dist/main.js.
import { Modal, Notice, Plugin, Setting } from 'obsidian';
import { seal, encodeEnvelope } from '../../site/public/lib/envelope.js';

// Your Magic Router deployment origin (or a self-hosted instance).
const HOST = 'https://YOUR-HOST';

class PasswordModal extends Modal {
  constructor(app, onSubmit) {
    super(app);
    this.onSubmit = onSubmit;
  }
  onOpen() {
    const { contentEl } = this;
    contentEl.createEl('h3', { text: 'Seal with password' });
    const input = contentEl.createEl('input', { type: 'password', placeholder: 'password' });
    input.focus();
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.close();
        this.onSubmit(input.value);
      }
    });
    new Setting(contentEl)
      .addButton((b) => b.setButtonText('Seal').onClick(() => {
        this.close();
        this.onSubmit(input.value);
      }));
  }
  onClose() {
    this.contentEl.empty();
  }
}

export default class SealLinkPlugin extends Plugin {
  async onload() {
    this.addCommand({
      id: 'seal-link',
      name: 'Seal link',
      editorCallback: async (editor) => {
        const url = editor.getSelection().trim();
        if (!url) {
          new Notice('Select a URL first');
          return;
        }
        new PasswordModal(this.app, async (password) => {
          try {
            const env = await seal({ type: 'url', data: url, passwords: [password] });
            const frag = await encodeEnvelope(env);
            const link = `${HOST}/#${frag}`;
            await navigator.clipboard.writeText(link);
            new Notice('Sealed link copied to clipboard');
          } catch (e) {
            new Notice('Sealing failed: ' + (e?.message || e));
          }
        }).open();
      },
    });
  }
}
