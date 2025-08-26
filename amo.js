class OAuthClient {
    constructor() {
        this.proxyUrl = 'https://your-domain.com/token_exchange.php';
    }

    async exchangeCode(code, redirectUri, codeVerifier) {
        try {
            const response = await fetch(this.proxyUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    code: code,
                    redirect_uri: redirectUri,
                    code_verifier: codeVerifier
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error_description || 'Token exchange failed');
            }

            const tokenData = await response.json();
            
            // Сохраняем токены
            this.storeTokens(tokenData);
            
            return tokenData;
            
        } catch (error) {
            console.error('Token exchange error:', error);
            throw error;
        }
    }

    storeTokens(tokenData) {
        localStorage.setItem('access_token', tokenData.access_token);
        if (tokenData.refresh_token) {
            localStorage.setItem('refresh_token', tokenData.refresh_token);
        }
        localStorage.setItem('expires_at', Date.now() + (tokenData.expires_in * 1000));
    }

    // Обработка callback из OAuth провайдера
    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const error = urlParams.get('error');
        const state = urlParams.get('state');

        if (error) {
            this.showError(`OAuth error: ${error}`);
            return;
        }

        if (!code) {
            this.showError('No authorization code received');
            return;
        }

        try {
            const codeVerifier = localStorage.getItem('code_verifier');
            const tokenData = await this.exchangeCode(
                code, 
                window.location.origin + window.location.pathname,
                codeVerifier
            );
            
            // Перенаправляем на главную страницу
            window.location.href = '/';
            
        } catch (error) {
            this.showError(`Token exchange failed: ${error.message}`);
        }
    }
}