let registerOptions = null;
const is_l3_available = () => !!globalThis.PublicKeyCredential?.parseCreationOptionsFromJSON;

export async function load_challenge(url_challenge) {
    if (!(navigator.credentials.create && await PublicKeyCredential.isConditionalMediationAvailable)) {
        return false;
    }

    const res = await fetch(url_challenge, { method: 'POST' });
    registerOptions = await res.json()
        .then(r => parse_request(r.publicKey));

    // Common configuration
    registerOptions.authenticatorSelection = publicKey.authenticatorSelection || {};
    registerOptions.authenticatorSelection['authenticatorAttachment'] = "platform";
    registerOptions.authenticatorSelection['residentKey'] = "preferred";
    registerOptions.authenticatorSelection['userVerification'] = "preferred";
    if (registerOptions.authenticatorSelection.requireResidentKey !== undefined) {
        delete registerOptions.authenticatorSelection.requireResidentKey;
    }

    return registerOptions;
}

export async function register_passkey(url_register, dom_form = null, input_key = "credential") {
    if (!registerOptions) return;

    try {
        const credential = await navigator.credentials.create({ publicKey: registerOptions });
    } catch (e) {
        alert(`Error on device: ${e}`);
        return;
    }
    try {
        return await submit_credential(url_register, credential, dom_form, input_key);
    } catch (e) { console.error(e); }
}

function parse_request(publicKey) {
    if (is_l3_available()) {
        return PublicKeyCredential.parseCreationOptionsFromJSON(publicKey);
    }

    publicKey.user.id = base64url2ab(publicKey.user.id);
    publicKey.challenge = base64url2ab(publicKey.challenge);
    publicKey.excludeCredentials?.forEach(ex => {
        ex.id = base64url2ab(ex.id);
    });
    return publicKey;
}

async function submit_credential(url_register, credential, dom_form = null, input_key = "credential") {
    if (!credential) return;

    let credential_json;
    if (is_l3_available()) {
        credential_json = credential.toJSON();
    } else {
        credential_json = serialize_fallback(credential);
    }
    credential_json = JSON.stringify(credential_json);

    if(dom_form && input_key) {
        try {
            dom_form[input_key].value = credential_json;
        } catch (e) {
            throw `HTMLform setup: ${e}`;
        }
        dom_form.submit();
        return;
    }

    return await fetch(url_register, {
        method: 'POST',
        body: credential_json,
        headers: {
            'Content-Type': 'application/json',
            'X-Register-Device': document.querySelector('input#agent')?.value
        }
    });
}

function serialize_fallback(pubkey_credential) {
    return {
        id: pubkey_credential.id,
        rawId: ab2base64url(pubkey_credential.rawId),
        type: pubkey_credential.type,
        response: {
            attestationObject: ab2base64url(pubkey_credential.response.attestationObject),
            clientDataJSON: ab2base64url(pubkey_credential.response.clientDataJSON)
        }
    };
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

function ab2base64url(ab) {
    function base642base64url(base64) {
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=*$/g, '')
    }

    const str = String.fromCharCode.apply(null, new Uint8Array(ab))
    return base642base64url(window.btoa(str));
}
