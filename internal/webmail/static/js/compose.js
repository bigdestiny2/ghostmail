// GhostMail Compose Modal
const Compose = {
    modal: null,
    onSent: null,

    init() {
        this.modal = document.getElementById('compose-modal');
        document.getElementById('compose-cancel').onclick = () => this.close();
        document.getElementById('compose-send').onclick = () => this.send();
        document.querySelector('.compose-header .close-btn').onclick = () => this.close();

        // Close on overlay click
        this.modal.onclick = (e) => {
            if (e.target === this.modal) this.close();
        };

        // Ctrl+Enter to send
        document.getElementById('compose-body').onkeydown = (e) => {
            if (e.ctrlKey && e.key === 'Enter') this.send();
        };
    },

    open(opts = {}) {
        document.getElementById('compose-to').value = opts.to || '';
        document.getElementById('compose-cc').value = opts.cc || '';
        document.getElementById('compose-subject').value = opts.subject || '';
        document.getElementById('compose-body').value = opts.body || '';
        document.getElementById('compose-in-reply-to').value = opts.inReplyTo || '';
        this.modal.classList.remove('hidden');
        document.getElementById('compose-to').focus();
    },

    close() {
        this.modal.classList.add('hidden');
    },

    async send() {
        const to = document.getElementById('compose-to').value.trim();
        const cc = document.getElementById('compose-cc').value.trim();
        const subject = document.getElementById('compose-subject').value.trim();
        const body = document.getElementById('compose-body').value;
        const inReplyTo = document.getElementById('compose-in-reply-to').value;

        if (!to || !subject) {
            alert('To and Subject are required');
            return;
        }

        const sendBtn = document.getElementById('compose-send');
        sendBtn.disabled = true;
        sendBtn.textContent = 'Sending...';

        try {
            const result = await API.sendMessage({ to, cc, subject, body, in_reply_to: inReplyTo });
            if (result.ok) {
                this.close();
                if (this.onSent) this.onSent();
            } else if (result.errors) {
                alert('Delivery errors:\n' + result.errors.join('\n'));
            }
        } catch (err) {
            alert('Send failed: ' + err.message);
        } finally {
            sendBtn.disabled = false;
            sendBtn.textContent = 'Send';
        }
    },

    reply(msg) {
        const reSubject = msg.subject.startsWith('Re:') ? msg.subject : 'Re: ' + msg.subject;
        const quotedBody = '\n\n--- Original Message ---\n' +
            'From: ' + msg.from + '\n' +
            'Date: ' + msg.date + '\n\n' +
            (msg.body_text || '').split('\n').map(l => '> ' + l).join('\n');
        this.open({
            to: msg.from,
            subject: reSubject,
            body: quotedBody,
            inReplyTo: msg.messageId || '',
        });
    },

    forward(msg) {
        const fwdSubject = msg.subject.startsWith('Fwd:') ? msg.subject : 'Fwd: ' + msg.subject;
        const fwdBody = '\n\n--- Forwarded Message ---\n' +
            'From: ' + msg.from + '\n' +
            'To: ' + msg.to + '\n' +
            'Date: ' + msg.date + '\n' +
            'Subject: ' + msg.subject + '\n\n' +
            (msg.body_text || '');
        this.open({
            to: '',
            subject: fwdSubject,
            body: fwdBody,
        });
    },
};
