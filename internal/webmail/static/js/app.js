// GhostMail Webmail SPA Controller
const App = {
    state: {
        mailboxes: [],
        currentMailbox: null,
        currentMailboxID: null,
        messages: [],
        currentMessage: null,
        currentPage: 1,
        totalMessages: 0,
        aliases: [],
        searchMode: false,
    },

    async init() {
        Compose.init();
        Compose.onSent = () => this.refreshMessages();

        // Bind events via addEventListener (CSP-safe, no inline handlers)
        document.getElementById('compose-new').addEventListener('click', () => Compose.open());
        document.getElementById('search-input').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.doSearch(e.target.value);
        });
        document.getElementById('logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('create-alias-btn').addEventListener('click', () => this.createAlias());

        // Event delegation for dynamically rendered elements
        document.getElementById('mailbox-list').addEventListener('click', (e) => {
            const item = e.target.closest('[data-mailbox]');
            if (item) this.selectMailbox(item.dataset.mailbox);
        });

        document.getElementById('message-items').addEventListener('click', (e) => {
            const star = e.target.closest('[data-star-mailbox]');
            if (star) {
                e.stopPropagation();
                this.toggleFlag(
                    parseInt(star.dataset.starMailbox, 10),
                    parseInt(star.dataset.starUid, 10),
                    '\\Flagged'
                );
                return;
            }
            const item = e.target.closest('[data-msg-mailbox]');
            if (item) {
                this.openMessage(
                    parseInt(item.dataset.msgMailbox, 10),
                    parseInt(item.dataset.msgUid, 10)
                );
            }
        });

        document.getElementById('message-pagination').addEventListener('click', (e) => {
            const btn = e.target.closest('[data-page-action]');
            if (!btn) return;
            if (btn.dataset.pageAction === 'prev') this.prevPage();
            if (btn.dataset.pageAction === 'next') this.nextPage();
        });

        document.getElementById('reader-content').addEventListener('click', (e) => {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;
            switch (btn.dataset.action) {
                case 'reply': Compose.reply(this.state.currentMessage); break;
                case 'forward': Compose.forward(this.state.currentMessage); break;
                case 'share-otv': this.shareOTV(); break;
                case 'delete': this.deleteCurrentMessage(); break;
                case 'move-trash': this.moveCurrentMessage('Trash'); break;
            }
        });

        document.getElementById('alias-list').addEventListener('click', (e) => {
            const del = e.target.closest('[data-delete-alias]');
            if (del) this.deleteAlias(parseInt(del.dataset.deleteAlias, 10));
        });

        // Load initial data
        await this.loadMailboxes();
        await this.loadAliases();

        // Select INBOX by default
        if (this.state.mailboxes.length > 0) {
            const inbox = this.state.mailboxes.find(m => m.name === 'INBOX') || this.state.mailboxes[0];
            this.selectMailbox(inbox.name);
        }
    },

    // --- Mailboxes ---
    async loadMailboxes() {
        try {
            this.state.mailboxes = await API.listMailboxes();
            this.renderMailboxes();
        } catch (err) {
            console.error('Failed to load mailboxes:', err);
        }
    },

    renderMailboxes() {
        const list = document.getElementById('mailbox-list');
        const icons = {
            'INBOX': '\u{1F4E5}', 'Sent': '\u{1F4E4}', 'Drafts': '\u{1F4DD}',
            'Trash': '\u{1F5D1}', 'Spam': '\u{26A0}'
        };

        list.innerHTML = this.state.mailboxes.map(mb => {
            const icon = icons[mb.name] || '\u{1F4C1}';
            const active = mb.name === this.state.currentMailbox ? 'active' : '';
            const countClass = mb.unread > 0 ? '' : 'zero';
            const safeName = this.escapeHtml(mb.name);
            return `<div class="mailbox-item ${active}" data-mailbox="${this.escapeAttr(mb.name)}">
                <span class="icon">${icon}</span>
                <span>${safeName}</span>
                <span class="count ${countClass}">${mb.unread}</span>
            </div>`;
        }).join('');
    },

    async selectMailbox(name) {
        this.state.currentMailbox = name;
        this.state.currentPage = 1;
        this.state.searchMode = false;
        this.state.currentMessage = null;

        // Find mailbox numeric ID
        const mb = this.state.mailboxes.find(m => m.name === name);
        this.state.currentMailboxID = mb ? mb.id : 0;

        this.renderMailboxes();
        this.renderReaderEmpty();
        await this.loadMessages();
    },

    // --- Messages ---
    async loadMessages() {
        const listEl = document.getElementById('message-items');
        listEl.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';

        try {
            const data = await API.listMessages(
                this.state.currentMailbox,
                this.state.currentPage,
                50
            );
            this.state.messages = data.messages || [];
            this.state.totalMessages = data.total || 0;
            this.renderMessages();
        } catch (err) {
            listEl.innerHTML = '<div class="message-list-empty">Failed to load messages</div>';
        }
    },

    async refreshMessages() {
        await this.loadMailboxes();
        if (this.state.currentMailbox) {
            await this.loadMessages();
        }
    },

    renderMessages() {
        const headerEl = document.getElementById('message-list-header');
        headerEl.innerHTML = `
            <span class="mailbox-name">${this.state.searchMode ? 'Search Results' : this.escapeHtml(this.state.currentMailbox || '')}</span>
            <span class="msg-count">${this.state.totalMessages} messages</span>`;

        const listEl = document.getElementById('message-items');
        if (this.state.messages.length === 0) {
            listEl.innerHTML = '<div class="message-list-empty">No messages</div>';
            this.renderPagination();
            return;
        }

        listEl.innerHTML = this.state.messages.map(msg => {
            const unread = msg.unread ? 'unread' : '';
            const active = this.state.currentMessage && this.state.currentMessage.uid === msg.uid ? 'active' : '';
            const flagged = (msg.flags || '').includes('\\Flagged') ? 'flagged' : '';
            const from = this.escapeHtml(msg.from || '(unknown)');
            const subject = this.escapeHtml(msg.subject || '(no subject)');
            const date = msg.date || '';
            const mailboxID = msg.mailboxID || this.state.currentMailboxID;

            return `<div class="message-item ${unread} ${active}"
                         data-msg-mailbox="${mailboxID}" data-msg-uid="${msg.uid}">
                <span class="msg-star ${flagged}"
                      data-star-mailbox="${mailboxID}" data-star-uid="${msg.uid}">
                    ${flagged ? '\u2605' : '\u2606'}
                </span>
                <span class="msg-from">${from}</span>
                <span class="msg-date">${date}</span>
                <span class="msg-subject">${subject}</span>
            </div>`;
        }).join('');

        this.renderPagination();
    },

    renderPagination() {
        const el = document.getElementById('message-pagination');
        const totalPages = Math.ceil(this.state.totalMessages / 50) || 1;
        if (totalPages <= 1) {
            el.innerHTML = '';
            return;
        }
        el.innerHTML = `
            <button class="btn btn-ghost btn-sm" data-page-action="prev" ${this.state.currentPage <= 1 ? 'disabled' : ''}>Prev</button>
            <span style="color: var(--text-muted); font-size: 0.8rem;">Page ${this.state.currentPage} of ${totalPages}</span>
            <button class="btn btn-ghost btn-sm" data-page-action="next" ${this.state.currentPage >= totalPages ? 'disabled' : ''}>Next</button>`;
    },

    async prevPage() {
        if (this.state.currentPage > 1) {
            this.state.currentPage--;
            await this.loadMessages();
        }
    },

    async nextPage() {
        this.state.currentPage++;
        await this.loadMessages();
    },

    // --- Reader ---
    async openMessage(mailboxID, uid) {
        const readerEl = document.getElementById('reader-content');
        readerEl.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';

        try {
            const msg = await API.getMessage(mailboxID, uid);
            msg._mailboxID = mailboxID;
            this.state.currentMessage = msg;

            // Mark as read in the list
            const listMsg = this.state.messages.find(m => m.uid === uid);
            if (listMsg) {
                listMsg.unread = false;
                listMsg.flags = msg.flags;
            }
            this.renderMessages();
            this.renderReader(msg);

            // Refresh mailbox counts
            this.loadMailboxes();
        } catch (err) {
            readerEl.innerHTML = '<div class="reader-empty">Failed to load message</div>';
        }
    },

    renderReader(msg) {
        const el = document.getElementById('reader-content');
        const bodyContent = msg.body_html
            ? '<div class="reader-body"><iframe sandbox="" srcdoc="' + msg.body_html.replace(/"/g, '&quot;') + '" class="reader-body-frame"></iframe></div>'
            : '<div class="reader-body">' + this.escapeHtml(msg.body_text || '') + '</div>';

        el.innerHTML = `
            <div class="reader-header">
                <div class="reader-subject">${this.escapeHtml(msg.subject || '(no subject)')}</div>
                <dl class="reader-meta">
                    <dt>From</dt><dd>${this.escapeHtml(msg.from || '')}</dd>
                    <dt>To</dt><dd>${this.escapeHtml(msg.to || '')}</dd>
                    ${msg.cc ? `<dt>CC</dt><dd>${this.escapeHtml(msg.cc)}</dd>` : ''}
                    <dt>Date</dt><dd>${msg.date || ''}</dd>
                </dl>
                <div class="reader-actions">
                    <button class="btn btn-ghost btn-sm" data-action="reply">Reply</button>
                    <button class="btn btn-ghost btn-sm" data-action="forward">Forward</button>
                    <button class="btn btn-ghost btn-sm" data-action="share-otv">Share Link</button>
                    <button class="btn btn-danger btn-sm" data-action="delete">Delete</button>
                    <button class="btn btn-ghost btn-sm" data-action="move-trash">Move to Trash</button>
                </div>
            </div>
            ${bodyContent}`;
    },

    renderReaderEmpty() {
        document.getElementById('reader-content').innerHTML =
            '<div class="reader-empty">Select a message to read</div>';
    },

    // --- Actions ---
    async toggleFlag(mailboxID, uid, flag) {
        const msg = this.state.messages.find(m => m.uid === uid);
        if (!msg) return;

        const has = (msg.flags || '').includes(flag);
        try {
            await API.updateFlags(mailboxID, uid, has ? [] : [flag], has ? [flag] : []);
            if (has) {
                msg.flags = (msg.flags || '').replace(flag, '').trim();
            } else {
                msg.flags = ((msg.flags || '') + ' ' + flag).trim();
            }
            this.renderMessages();
        } catch (err) {
            console.error('Flag update failed:', err);
        }
    },

    async deleteCurrentMessage() {
        const msg = this.state.currentMessage;
        if (!msg) return;
        try {
            await API.deleteMessage(msg._mailboxID, msg.uid);
            this.state.currentMessage = null;
            this.renderReaderEmpty();
            await this.refreshMessages();
        } catch (err) {
            alert('Delete failed: ' + err.message);
        }
    },

    async moveCurrentMessage(dest) {
        const msg = this.state.currentMessage;
        if (!msg) return;
        try {
            await API.moveMessage(msg._mailboxID, msg.uid, dest);
            this.state.currentMessage = null;
            this.renderReaderEmpty();
            await this.refreshMessages();
        } catch (err) {
            alert('Move failed: ' + err.message);
        }
    },

    // --- One-Time View ---
    async shareOTV() {
        const msg = this.state.currentMessage;
        if (!msg) return;
        try {
            const result = await API.createOTV(msg._mailboxID, msg.uid);
            if (result.url) {
                // Copy to clipboard and show
                if (navigator.clipboard) {
                    await navigator.clipboard.writeText(result.url);
                    alert('One-time view link copied to clipboard!\n\nExpires in 5 minutes. Can only be opened once.\n\n' + result.url);
                } else {
                    prompt('One-time view link (expires in 5 min, single use):', result.url);
                }
            }
        } catch (err) {
            alert('Failed to create view link: ' + err.message);
        }
    },

    // --- Search ---
    async doSearch(query) {
        if (!query.trim()) {
            this.state.searchMode = false;
            if (this.state.currentMailbox) {
                await this.loadMessages();
            }
            return;
        }

        this.state.searchMode = true;
        const listEl = document.getElementById('message-items');
        listEl.innerHTML = '<div class="loading"><div class="spinner"></div> Searching...</div>';

        try {
            const data = await API.search(query, this.state.currentMailbox);
            this.state.messages = data.messages || [];
            this.state.totalMessages = data.total || 0;
            this.renderMessages();
        } catch (err) {
            listEl.innerHTML = '<div class="message-list-empty">Search failed</div>';
        }
    },

    // --- Aliases ---
    async loadAliases() {
        try {
            this.state.aliases = await API.listAliases();
            this.renderAliases();
        } catch (err) {
            console.error('Failed to load aliases:', err);
        }
    },

    renderAliases() {
        const list = document.getElementById('alias-list');
        if (this.state.aliases.length === 0) {
            list.innerHTML = '<div class="alias-item"><span class="alias-addr">No aliases yet</span></div>';
            return;
        }
        list.innerHTML = this.state.aliases.map(a => {
            const addr = this.escapeHtml(a.address.split('@')[0]);
            const status = a.is_active ? '' : ' (inactive)';
            const safeTitle = this.escapeAttr(a.address + status);
            const aliasId = parseInt(a.id, 10);
            return `<div class="alias-item" title="${safeTitle}">
                <span class="alias-addr">${addr}${status}</span>
                <span class="alias-delete" data-delete-alias="${aliasId}">\u00D7</span>
            </div>`;
        }).join('');
    },

    async createAlias() {
        const desc = prompt('Alias description (optional):') || '';
        try {
            await API.createAlias(desc);
            await this.loadAliases();
        } catch (err) {
            alert('Failed to create alias: ' + err.message);
        }
    },

    async deleteAlias(id) {
        if (!confirm('Delete this alias?')) return;
        try {
            await API.deleteAlias(id);
            await this.loadAliases();
        } catch (err) {
            alert('Failed to delete alias: ' + err.message);
        }
    },

    // --- Auth ---
    async logout() {
        await API.logout();
        window.location.href = '/mail/login';
    },

    // --- Helpers ---
    escapeHtml(s) {
        const div = document.createElement('div');
        div.textContent = s;
        return div.innerHTML;
    },

    escapeAttr(s) {
        return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    },
};

// Boot
document.addEventListener('DOMContentLoaded', () => App.init());
