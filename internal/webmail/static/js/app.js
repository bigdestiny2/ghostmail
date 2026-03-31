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

        // Bind events
        document.getElementById('compose-new').onclick = () => Compose.open();
        document.getElementById('search-input').onkeydown = (e) => {
            if (e.key === 'Enter') this.doSearch(e.target.value);
        };
        document.getElementById('logout-btn').onclick = () => this.logout();
        document.getElementById('create-alias-btn').onclick = () => this.createAlias();

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
            const attrName = mb.name.replace(/'/g, "\\'").replace(/"/g, '&quot;');
            return `<div class="mailbox-item ${active}" onclick="App.selectMailbox('${attrName}')">
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

        // Find mailbox ID
        const mb = this.state.mailboxes.find(m => m.name === name);
        this.state.currentMailboxID = mb ? mb.name : name;

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
            const mailboxID = msg.mailboxID || this.getMailboxID(this.state.currentMailbox);

            return `<div class="message-item ${unread} ${active}"
                         onclick="App.openMessage(${mailboxID}, ${msg.uid})">
                <span class="msg-star ${flagged}"
                      onclick="event.stopPropagation(); App.toggleFlag(${mailboxID}, ${msg.uid}, '\\\\Flagged')">
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
            <button class="btn btn-ghost btn-sm" onclick="App.prevPage()" ${this.state.currentPage <= 1 ? 'disabled' : ''}>Prev</button>
            <span style="color: var(--text-muted); font-size: 0.8rem;">Page ${this.state.currentPage} of ${totalPages}</span>
            <button class="btn btn-ghost btn-sm" onclick="App.nextPage()" ${this.state.currentPage >= totalPages ? 'disabled' : ''}>Next</button>`;
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
                    <button class="btn btn-ghost btn-sm" onclick="Compose.reply(App.state.currentMessage)">Reply</button>
                    <button class="btn btn-ghost btn-sm" onclick="Compose.forward(App.state.currentMessage)">Forward</button>
                    <button class="btn btn-danger btn-sm" onclick="App.deleteCurrentMessage()">Delete</button>
                    <button class="btn btn-ghost btn-sm" onclick="App.moveCurrentMessage('Trash')">Move to Trash</button>
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
            const safeTitle = this.escapeHtml(a.address + status);
            return `<div class="alias-item" title="${safeTitle}">
                <span class="alias-addr">${addr}${status}</span>
                <span class="alias-delete" onclick="App.deleteAlias(${parseInt(a.id, 10)})">\u00D7</span>
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
    getMailboxID(name) {
        // For search results that include mailboxID
        const mb = this.state.mailboxes.find(m => m.name === name);
        return mb ? mb.name : name;
    },

    escapeHtml(s) {
        const div = document.createElement('div');
        div.textContent = s;
        return div.innerHTML;
    },
};

// Boot
document.addEventListener('DOMContentLoaded', () => App.init());
