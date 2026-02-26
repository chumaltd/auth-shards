async function register_passkey() {
    let publicKey;
    let credential_json;
    try {
        const res_challenge = await fetch('/auth/webauthn/register/challenge', { method: 'POST' });
        publicKey = await res_challenge.json().then(r => r.publicKey);

        // Common configuration
        publicKey.authenticatorSelection = publicKey.authenticatorSelection || {};
        publicKey.authenticatorSelection['authenticatorAttachment'] = "platform";
        publicKey.authenticatorSelection['residentKey'] = "preferred";
        publicKey.authenticatorSelection['userVerification'] = "preferred";
        if (publicKey.authenticatorSelection.requireResidentKey !== undefined) {
            delete publicKey.authenticatorSelection.requireResidentKey;
        }

        if (globalThis.PublicKeyCredential?.parseCreationOptionsFromJSON) {
            credential_json = await register_passkey_l3(publicKey);
        } else {
            credential_json = await register_passkey_fallback(publicKey);
        }

        if (!credential_json) return;

        const res_register = await fetch('/auth/webauthn/register/apply', {
            method: 'POST',
            body: JSON.stringify(credential_json),
            headers: {
                'Content-Type': 'application/json',
                'X-Register-Device': document.querySelector('input#agent').value
            }
        });
        location = '/auth/account?passkey_registered';
    } catch (e) { console.error(e); }
}

async function register_passkey_l3(publicKey) {
    try {
        const options = PublicKeyCredential.parseCreationOptionsFromJSON(publicKey);
        const credential = await navigator.credentials.create({ publicKey: options });
        return credential.toJSON();
    } catch (e) {
        alert(`Error on device: ${e}`);
        return null;
    }
}

async function register_passkey_fallback(publicKey) {
    publicKey.user.id = base64url2ab(publicKey.user.id);
    publicKey.challenge = base64url2ab(publicKey.challenge);
    publicKey.excludeCredentials?.forEach(ex => {
        ex.id = base64url2ab(ex.id);
    });

    let pubkey_credential;
    try {
        pubkey_credential = await navigator.credentials.create({ publicKey });
    } catch (e) {
        alert(`Error on device: ${e}`);
        return null;
    }

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
