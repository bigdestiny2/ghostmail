// GhostMail Webmail API Client
const API = {
    async request(method, path, body) {
        const opts = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'X-GhostMail-CSRF': '1',
            },
            credentials: 'same-origin',
        };
        if (body) opts.body = JSON.stringify(body);

        const res = await fetch('/api/v1' + path, opts);
        if (res.status === 401) {
            window.location.href = '/mail/login';
            return null;
        }
        const data = await res.json();
        if (!res.ok && data.error) throw new Error(data.error);
        return data;
    },

    // Auth
    login(email, password) {
        return this.request('POST', '/auth/login', { email, password });
    },
    logout() {
        return this.request('POST', '/auth/logout');
    },

    // Mailboxes
    listMailboxes() {
        return this.request('GET', '/mailboxes');
    },

    // Messages
    listMessages(mailbox, page = 1, limit = 50) {
        return this.request('GET', `/mailboxes/${encodeURIComponent(mailbox)}/messages?page=${page}&limit=${limit}`);
    },
    getMessage(mailboxID, uid) {
        return this.request('GET', `/messages/${mailboxID}/${uid}`);
    },
    sendMessage(data) {
        return this.request('POST', '/messages/send', data);
    },
    updateFlags(mailboxID, uid, add, remove) {
        return this.request('POST', `/messages/${mailboxID}/${uid}/flags`, { add, remove });
    },
    moveMessage(mailboxID, uid, destination) {
        return this.request('POST', `/messages/${mailboxID}/${uid}/move`, { destination });
    },
    deleteMessage(mailboxID, uid) {
        return this.request('DELETE', `/messages/${mailboxID}/${uid}`);
    },

    // Search
    search(query, mailbox) {
        return this.request('POST', '/search', { query, mailbox });
    },

    // Aliases
    listAliases() {
        return this.request('GET', '/aliases');
    },
    createAlias(description, domain) {
        return this.request('POST', '/aliases', { description, domain });
    },
    deleteAlias(id) {
        return this.request('DELETE', `/aliases/${id}`);
    },

    // One-Time View (OTV)
    createOTV(mailboxID, uid) {
        return this.request('POST', '/otv/create', { mailbox_id: mailboxID, uid: uid });
    },
};
