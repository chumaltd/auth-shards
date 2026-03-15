let authnOptions = null;
let abortController = new AbortController();
const is_l3_available = () => !!globalThis.PublicKeyCredential?.parseRequestOptionsFromJSON;
let redirect_url;

async function is_passkey_operation_available() {
    return !!(
        navigator.credentials?.get
        && globalThis.PublicKeyCredential?.isConditionalMediationAvailable
    );
}

export async function load_challenge(source) {
    if (!(await is_passkey_operation_available())) {
        return false;
    }

    const response = await resolve_challenge_source(source);
    if (!response) return false;
    authnOptions = parse_request(response);
    return authnOptions;
}

export function update_redirect(url) {
    const target = new URL(url, location.origin);
    try {
        if (/^https?:/.test(target.protocol) && target.origin === location.origin) {
            redirect_url ||= target.pathname + target.search + target.hash;
        }
    } catch(e) { console.error(`${e.name}: ${e.message}`); }
    redirect_url ||= 1;
}

export async function setup_conditional(endpoint, input_key = "credential") {
    if (!endpoint instanceof HTMLElement && !typeof endpoint == 'string') {
        throw new Error('endpoint should be URL string or form DOM.');
    }
    if (!authnOptions) return;

    try {
        const credential = await navigator.credentials.get({
            publicKey: authnOptions.publicKey,
            mediation: 'conditional',
            signal: abortController.signal
        });
        return submit_credential(endpoint, credential, input_key);
    } catch (err) {
        if (err.name !== 'AbortError') console.error(err);
    }
}

export async function passkey_btn_handler(endpoint, input_key = "credential") {
    if (!endpoint instanceof HTMLElement && !typeof endpoint == 'string') {
        throw new Error('endpoint should be URL string or form DOM.');
    }
    if (!authnOptions) return;

    abortController?.abort();
    abortController = new AbortController();
    try {
        const options = {
            publicKey: authnOptions.publicKey,
            mediation: 'optional',
            signal: abortController.signal
        };
        const credential = await navigator.credentials.get(options);
        return submit_credential(endpoint, credential, input_key);
    } catch (err) {
        if (err.name !== 'AbortError') console.error(err);
    }
}

function resolve_challenge_source(source) {
    if (source instanceof HTMLElement) {
        const raw = source.dataset.options;
        if (!raw) return false;
        return JSON.parse(raw);
    }
    if (typeof source === 'string') {
        const trimmed = source.trim();
        if (trimmed.startsWith('{')) {
            return JSON.parse(trimmed);
        }
        return fetch(source, { method: 'POST' }).then(res => res.json());
    }
    if (typeof source === 'object' && source?.publicKey) {
        return source;
    }

    throw new Error('challenge source should be URL, DOM, or challenge object.');
}

function parse_request(response) {
    if (is_l3_available()) {
        return {
            publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(response.publicKey)
        };
    } else {
        response.publicKey.challenge = base64url2ab(response.publicKey.challenge);
        response.publicKey.allowCredentials?.forEach(ac => {
            ac.id = base64url2ab(ac.id);
        });
        return response;
    }
}

async function submit_credential(endpoint, credential, input_key = "credential") {
    if (!credential) return;

    let dom_form = null;
    let url_register = null;
    if (endpoint instanceof HTMLElement) {
        dom_form = endpoint;
    } else if (typeof endpoint === 'string') {
        url_register = endpoint;
    } else {
        throw new Error('endpoint should be URL string or form DOM.');
    }

    if (typeof redirect_url == 'string') {
        try {
            history.replaceState(null, '', redirect_url);
        } catch(e) { console.error(`history.replaceState() detected: ${e}`); }
    }
    let credential_json;
    if (is_l3_available()) {
        credential_json = credential.toJSON();
    } else {
        credential_json = serialize_fallback(credential);
    }
    if(dom_form && input_key) {
        try {
            dom_form[input_key].value = JSON.stringify(credential_json);
        } catch (e) {
            throw `HTMLform setup: ${e}`;
        }
        dom_form.submit();
        return;
    }

    return await fetch(url_register, {
        body: JSON.stringify(credential_json),
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
    });
}

function serialize_fallback(pubkey_credential) {
    return {
        id: pubkey_credential.id,
        rawId: ab2base64url(pubkey_credential.rawId),
        type: pubkey_credential.type,
        response: {
            authenticatorData: ab2base64url(pubkey_credential.response.authenticatorData),
            clientDataJSON: ab2base64url(pubkey_credential.response.clientDataJSON),
            signature: ab2base64url(pubkey_credential.response.signature),
            userHandle: ab2base64url(pubkey_credential.response.userHandle),
        },
        extensions: pubkey_credential.extensions
    };
}

function ab2base64url(ab) {
    function base642base64url(base64) {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=*$/g, '')
    }

    const str = String.fromCharCode.apply(null, new Uint8Array(ab))
    return base642base64url(window.btoa(str));
}

function base64url2ab(base64url) {
    function base642ab(base64) {
        const str = window.atob(base64);
        const len = str.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = str.charCodeAt(i);
        }
        return bytes.buffer;
    }
    function base64url2base64(base64url) {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = base64.length % 4;
        if (padding > 0) {
            return base64 + '===='.slice(padding);
        }
        return base64;
    }

    return base642ab(base64url2base64(base64url));
}
