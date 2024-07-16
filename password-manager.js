"use strict";

class SecurePasswordManager {
  constructor() {
    this.passwords = {};
    this.storage = localStorage;
    this.masterPasswordKey = 'masterPasswordHash';
    this.passwordsKey = 'passwords';
  }

  async hashPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: enc.encode(salt),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    const exportedKey = await crypto.subtle.exportKey('raw', key);
    return btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
  }

  async initMasterPassword(masterPassword) {
    const storedHash = this.storage.getItem(this.masterPasswordKey);
    if (storedHash) {
      const inputHash = await this.hashPassword(masterPassword, 'salt');
      if (inputHash !== storedHash) {
        throw new Error('Invalid master password.');
      }
    } else {
      const hash = await this.hashPassword(masterPassword, 'salt');
      this.storage.setItem(this.masterPasswordKey, hash);
    }
  }

  async savePasswords() {
    const encryptedData = btoa(JSON.stringify(this.passwords));
    this.storage.setItem(this.passwordsKey, encryptedData);
  }

  async loadPasswords() {
    const encryptedData = this.storage.getItem(this.passwordsKey);
    if (encryptedData) {
      this.passwords = JSON.parse(atob(encryptedData));
    } else {
      this.passwords = {};
    }
  }

  async addPassword(domain, password) {
    if (!domain || !password) {
      throw new Error('Domain and password are required.');
    }

    if (this.passwords[domain]) {
      throw new Error('Domain already exists.');
    }

    this.passwords[domain] = password;
    await this.savePasswords();
  }

  async getPassword(domain) {
    if (!domain) {
      throw new Error('Domain is required.');
    }

    return this.passwords[domain] || null;
  }

  async listPasswords() {
    return Object.keys(this.passwords).map(domain => ({
      domain,
      password: this.passwords[domain]
    }));
  }

  async deletePassword(domain) {
    if (!domain) {
      throw new Error('Domain is required.');
    }

    delete this.passwords[domain];
    await this.savePasswords();
  }
}

const passwordManager = new SecurePasswordManager();
document.getElementById('init-master-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const masterPassword = document.getElementById('master-password').value;
  try {
    await passwordManager.initMasterPassword(masterPassword);
    alert('Master password set/verified successfully!');
    await passwordManager.loadPasswords();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById('add-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const domain = document.getElementById('domain').value;
  const password = document.getElementById('password').value;
  try {
    await passwordManager.addPassword(domain, password);
    alert('Password added successfully!');
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById('get-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const domain = document.getElementById('get-domain').value;
  try {
    const password = await passwordManager.getPassword(domain);
    const resultElement = document.getElementById('get-password-result');
    if (password) {
      resultElement.textContent = `Password: ${password}`;
    } else {
      resultElement.textContent = 'Password not found';
    }
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById('list-passwords-button').addEventListener('click', async () => {
  try {
    const passwords = await passwordManager.listPasswords();
    const passwordsList = document.getElementById('passwords-list');
    passwordsList.innerHTML = '';
    passwords.forEach(entry => {
      const li = document.createElement('li');
      li.textContent = `Domain: ${entry.domain}, Password: ${entry.password}`;
      passwordsList.appendChild(li);
    });
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById('delete-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const domain = document.getElementById('delete-domain').value;
  try {
    await passwordManager.deletePassword(domain);
    alert('Password deleted successfully!');
  } catch (error) {
    alert(error.message);
  }
});
