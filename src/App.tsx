import React, { useEffect, useState } from 'react';

function App() {
  const clientId: string = import.meta.env.VITE_CLIENT_ID;
  const clientSecret: string = import.meta.env.VITE_CLIENT_SECRET;
  const redirectUri: string = import.meta.env.VITE_REDIRECT_URL;
  const authEndpoint: string = import.meta.env.VITE_AUTH_ENDPOINT;
  const responseType: string = import.meta.env.VITE_RESPONSE_TYPE;

  const [isAuthorized, setIsAuthorized] = useState<boolean>(false);
  const [loggedIn, setLoggedIn] = useState<boolean>(false);

  const generateRandomString = (length) => {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(length));
    return Array.from(values)
      .map((x) => possible[x % possible.length])
      .join('');
  };

  const codeVerifier = generateRandomString(64);

  const sha256 = async (plain) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    const buffer = await window.crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buffer))
      .map((x) => x.toString(16).padStart(2, '0'))
      .join('');
  };

  const base64encode = (input) => {
    return btoa(input)
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  };

  const handleLogin = () => { 
    // useEffect(() => {
      const initiateAuthorization = async () => {
        const codeVerifier = generateRandomString(64);
        const codeChallenge = await sha256(codeVerifier);
    
        const scope = 'user-library-read';
    
        const authUrl = new URL(authEndpoint);
    
        const authParams = new URLSearchParams({
          response_type: responseType,
          client_id: clientId,
          scope: scope,
          code_challenge_method: 'S256',
          code_challenge: base64encode(codeChallenge),
          redirect_uri: redirectUri,
        });
    
        authUrl.search = authParams.toString();
        console.log('Authorization URL:', authUrl.toString()); // Add this log
    
        // Redirect the user to the Spotify authorization page
        window.location.href = authUrl.toString();
      };
    
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get('code');
      console.log('Authorization code:', code);
  
      if (code) {
        // Authorization code is present in the URL
        // Perform the next steps to get the access token
        console.log('Authorization code:', code);
        setIsAuthorized(true);
        const codeVerifier = localStorage.getItem('code_verifier');
        getToken(code, codeVerifier);
      } else {
        // No authorization code, initiate the authorization flow
        console.log('No authorization code, initiating authorization');
      }
      initiateAuthorization();
      setLoggedIn(true)
    // }, []);
  }

  const getToken = async (code: string, codeVerifier: string): Promise<void> => {
    try {
      const response = await fetch('https://accounts.spotify.com/api/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
          body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: 'client_credentials',
          code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
        }),
      });
  
      if (!response.ok) {
        console.log('Token Request Failed');
        // Handle non-successful responses, e.g., unauthorized or bad request
        throw new Error(`Failed to get access token. Status: ${response.status}`);
      }
  
      const data = await response.json();
      const accessToken = data.access_token;
      console.log('Access Token:', accessToken);
      localStorage.setItem('access_token', accessToken);
    } catch (error) {
      console.error('Error getting access token:', error);
    }
  };


  const getRefreshToken = async (): Promise<void> => {

    // refresh token that has been previously stored
    const refreshToken = localStorage.getItem('refresh_token');
    const url = "https://accounts.spotify.com/api/token";
 
     const payload = {
       method: 'POST',
       headers: {
         'Content-Type': 'application/x-www-form-urlencoded'
       },
       body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: clientId
       } as Record<string, string>),
     }
     const body = await fetch(url, payload);
     const response = await body.json();
 
     localStorage.setItem('access_token', response.accessToken);
     localStorage.setItem('refresh_token', response.refreshToken);
   }

  


   const fetchData = async () => {
    try {
      const accessToken = localStorage.getItem('access_token');
      console.log('Access Token (from localStorage):', accessToken);
      const response = await fetch('https://api.spotify.com/v1/browse/new-releases', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        console.log('Top Tracks Request Failed');
        throw new Error(`Failed to fetch top tracks. Status: ${response.status}`);
      }

      const data = await response.json();
      console.log('Top Tracks:', data);
    } catch (error) {
      console.error('Error fetching top tracks:', error);
    }
  };



  const logOut = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('code_verifier');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('expires_at');
    setIsAuthorized(false);
    setLoggedIn(false) // Reset the authorization state
  };
  


  return (
    <>
      <div>
        <h1>Playlistify</h1>
        <button onClick={handleLogin}>Login to Spotify to Begin!</button>
        {isAuthorized ? (
        //   <a href={`${authEndpoint}?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=${responseType}`}>
          <button onClick={fetchData}>Make me a playlist</button>
        // </a>
        ) : (
          null
        )}
        { loggedIn ? <button onClick={logOut}>Log Out</button> : null}
      
      </div>
    </>
  );
}

export default App;