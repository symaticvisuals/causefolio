import jwtDecode from 'jwt-decode';
import axios from 'src/utils/axios';

import firebase from 'firebase';
require('firebase/auth');

class AuthService {
  // Configure Firebase.
  config = {
    apiKey: 'AIzaSyAuO7aI3q1rnl6OHwDHNKofyWGq-jUrI0U',
    authDomain: 'causefolio-12fc0.firebaseapp.com',
    projectId: 'causefolio-12fc0',
    storageBucket: 'causefolio-12fc0.appspot.com',
    messagingSenderId: '861094233182',
    appId: '1:861094233182:web:3749004d3e850b4dd8e0cf'
    // ...
  };

  // Configure FirebaseUI.
  uiConfig = {
    // Popup signin flow rather than redirect flow.
    signInFlow: 'popup',
    signInOptions: [firebase.auth.GoogleAuthProvider.PROVIDER_ID],
    callbacks: {
      // Avoid redirects after sign-in.
      signInSuccessWithAuthResult: () => false
    }
  };

  firebase = firebase;

  user = {};

  setAxiosInterceptors = ({ onLogout }) => {
    axios.interceptors.response.use(
      response => response,
      error => {
        if (error.response && error.response.status === 401) {
          this.setSession(null);

          if (onLogout) {
            onLogout();
          }
        }

        return Promise.reject(error);
      }
    );
  };

  handleAuthentication() {
    this.firebase.initializeApp(this.config);
  }

  signInWithEmailAndPassword(email, password) {
    return this.firebase.auth().signInWithEmailAndPassword(email, password);
  }

  login = () => {
    this.keycloak.init().then(authenticated => {
      if (!authenticated) {
        this.keycloak.login();
      }
    });
  };

  loginInWithToken = () =>
    new Promise((resolve, reject) => {
      axios
        .get('/api/account/me')
        .then(response => {
          if (response.data.user) {
            resolve(response.data.user);
          } else {
            reject(response.data.error);
          }
        })
        .catch(error => {
          reject(error);
        });
    });

  logout = () => {
    this.firebase.auth().signOut();
    this.setSession(null);
  };

  setSession = accessToken => {
    if (accessToken) {
      localStorage.setItem('accessToken', accessToken);
      axios.defaults.headers.common.Authorization = `Bearer ${accessToken}`;
    } else {
      localStorage.removeItem('accessToken');
      delete axios.defaults.headers.common.Authorization;
    }
  };

  getAccessToken = () => localStorage.getItem('accessToken');

  isValidToken = accessToken => {
    if (!accessToken) {
      return false;
    }

    const decoded = jwtDecode(accessToken);
    const currentTime = Date.now() / 1000;

    return decoded.exp > currentTime;
  };

  isAuthenticated = () => !!this.keycloak.authenticated;
}

const authService = new AuthService();

export default authService;
export { firebase };

export const signInWithGoogle = () => {
  const provider = new firebase.auth.GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  return firebase.auth().signInWithPopup(provider);
};

export const getLoggedUser = () => {
  return JSON.parse(localStorage.getItem('causefolioUser'));
};
