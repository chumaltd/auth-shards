let registerOptions = null;
const is_l3_available = () => !!globalThis.PublicKeyCredential?.parseCreationOptionsFromJSON;

export class PostError extends Error {
    static {
        this.prototype.name = "PostError";
    }
}

export async function load_challenge(source, replace = false) {
    if (!(navigator.credentials.create && await PublicKeyCredential.isConditionalMediationAvailable)) {
        return false;
    }

    const response = await resolve_challenge_source(source, replace);
    if (!response) return false;
    registerOptions = await Promise.resolve(response)
        .then(r => parse_request(r.publicKey));

    // Common configuration
    registerOptions.authenticatorSelection = registerOptions.authenticatorSelection || {};
    registerOptions.authenticatorSelection['authenticatorAttachment'] = "platform";
    registerOptions.authenticatorSelection['residentKey'] = "preferred";
    registerOptions.authenticatorSelection['userVerification'] = "preferred";
    if (registerOptions.authenticatorSelection.requireResidentKey !== undefined) {
        delete registerOptions.authenticatorSelection.requireResidentKey;
    }

    return registerOptions;
}

export function redirect_on_error(error, redirect_path = "#") {
              switch(error.name) {
              case 'NotSupportedError':
                  console.error(`${error.name}: Device cannot register passkey: ${error.massage}`);
                  location.replace(`${redirect_path}?passkey_not_supported`);
                  break;
              case 'NotReadableError':
                  console.error(`${error.name}: Device refused registration: ${error.massage}`);
                  location.replace(`${redirect_path}?passkey_not_readable`);
                  break;
              case 'NotAllowedError':
                  console.error(`${error.name}: Passkey duplicated or cancelled: ${error.massage}`);
                  location.replace(`${redirect_path}?passkey_not_allowed`);
                  break;
              case 'InvalidStateError':
                  console.error(`${error.name}: Passkey duplicated: ${error.massage}`);
                  location.replace(`${redirect_path}?passkey_invalid_state`);
                  break;
              case 'PostError':
                  console.error(`${error.name}: Server communication failed: ${error.massage}`);
                  location.replace(`${redirect_path}?passkey_post_failure`);
              default:
                  throw error;
              }
}

export async function register_passkey(endpoint, input_key = "credential") {
    if (!endpoint instanceof HTMLElement && !typeof endpoint == 'string') {
        throw new Error('endpoint should be URL string or form DOM.');
    }
    if (!registerOptions) return;

    const credential = await navigator.credentials.create({ publicKey: registerOptions });
    return await submit_credential(endpoint, credential, input_key);
}

async function resolve_challenge_source(source, replace = false) {
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

        const body = new URLSearchParams();
        if (replace) {
            body.set('replace', 'true');
        }
        const res = await fetch(source, {
            method: 'POST',
            body: body.toString(),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });
        return await res.json();
    }
    if (typeof source === 'object' && source?.publicKey) {
        return source;
    }

    throw new Error('challenge source should be URL, DOM, or challenge object.');
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

async function submit_credential(endpoint, credential, input_key = "credential") {
    if (!credential) return;

    let dom_form = null;
    let url_register = null;
    if (endpoint instanceof HTMLElement) {
        dom_form = endpoint;
    } else if (typeof endpoint == 'string') {
        url_register = endpoint;
    } else {
        throw new Error('endpoint should be URL string or form DOM.');
    }
    let credential_json;
    if (is_l3_available()) {
        credential_json = credential.toJSON();
    } else {
        credential_json = serialize_fallback(credential);
    }
    credential_json = JSON.stringify(credential_json);

    if (dom_form && input_key) {
        try {
            dom_form[input_key].value = credential_json;
        } catch (e) {
            throw new Error(`HTMLform setup failed`, { cause: e });
        }
        dom_form.submit();
        return;
    }

    return await fetch(url_register, {
        method: 'POST',
        body: credential_json,
        headers: {
            'Content-Type': 'application/json',
        }
    })
        .catch(e => { throw new PostError("Posting to server failed", { cause: e }); });
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
