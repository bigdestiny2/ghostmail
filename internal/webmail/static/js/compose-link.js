// Auto-open compose modal if compose link params are present
document.addEventListener('DOMContentLoaded', function() {
    var metaTo = document.querySelector('meta[name="compose-to"]');
    var metaSubject = document.querySelector('meta[name="compose-subject"]');
    var metaCC = document.querySelector('meta[name="compose-cc"]');
    var metaBody = document.querySelector('meta[name="compose-body"]');

    var composeTo = metaTo ? metaTo.content : '';
    var composeSubject = metaSubject ? metaSubject.content : '';
    var composeCC = metaCC ? metaCC.content : '';
    var composeBody = metaBody ? metaBody.content : '';

    if (composeTo || composeSubject) {
        setTimeout(function() {
            Compose.open({
                to: composeTo,
                subject: composeSubject,
                cc: composeCC,
                body: composeBody,
            });
        }, 500);
    }
});
