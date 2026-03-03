
export function can_register (dom, key = "current") {
    return !! dom.dataset[key];
}

export function register_delete (dom, btn_selector, callback_del, callback_replace = null, current_key = "current") {
    if (!dom) {
        console.error('Cannot register Passkey delete functions');
        return;
    }

    btn_selector = `${btn_selector}[data-id]`;
    const current_id = dom.dataset[current_key];
    const buttons = dom.querySelectorAll(btn_selector);
    dom.addEventListener('click', function(event) {
        const targetEl = event.target.closest(btn_selector);

        if(targetEl && dom.contains(targetEl)) {
            const id = targetEl.dataset.id;
            if (!id) return;

            if (buttons.length < 2 || id == current_id) {
                if (!callback_replace) return;

                callback_replace(id);
            } else {
                callback_del(id);
            }
        }
    });
    buttons.forEach(btn => {
        btn.disabled = false;
    })
}

export async function delete_passkey (url, id) {
    if (!id) {
        console.error("passkey not specified");
        return;
    }
    const req = new URLSearchParams({ id });

    const res = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: req.toString()
    });
    if (res.status == 200) {
        if (PublicKeyCredential.signalUnknownCredential) {
            const data = await res.json();
            await PublicKeyCredential.signalUnknownCredential({
                rpId: data.rpId,
                credentialId: data.id,
            });
            return { status: 0, message: "key deleted and signaled" }
        } else {
            return { status: 1, message: "key deleted and not signaled" }
        }
    }
}
