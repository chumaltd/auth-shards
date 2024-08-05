async function load_challenge(url) {
    if (!(navigator.credentials.get && await PublicKeyCredential.isConditionalMediationAvailable)) {
        return false;
    }

    const res_challenge = await fetch(url, { method: 'POST' });
    return await res_challenge.json();
}

async function webauthn_auth(url, response) {
    if (!(navigator.credentials.get && await PublicKeyCredential.isConditionalMediationAvailable)) {
        return false;
    }

    response.publicKey.challenge = base64url2ab(response.publicKey.challenge);
    response.publicKey.allowCredentials?.forEach(ac => {
        ac.id = base64url2ab(ac.id);
    });
    const pubkey_credential = await navigator.credentials.get(response);
    const credential = {
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
    return await fetch(url, {
        body: JSON.stringify(credential),
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
    });
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
