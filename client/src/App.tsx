import React, { useEffect, useState, useCallback } from "react";
import CryptoJS from "crypto-js"; // Import CryptoJS

const API_URL = "http://localhost:8080";

function App() {
  const [data, setData] = useState<string>("");
  const [secret, setSecret] = useState<string | null>(null);
  const [id, setId] = useState<string | null>(null);

  const showToast = (message: string) => {
    alert(message); // Replace with a better toast in production
  };

  const getTokenAndSecret = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/connect`, {
        credentials: "include",
      });
      const data = await response.json();
      setId(data.data.id);
      setSecret(data.data.secret);
      showToast("Connected successfully, secret retrieved.");
    } catch (error) {
      showToast("Error connecting to API.");
      console.error("Error connecting to API:", error);
    }
  }, []);

  useEffect(() => {
    getTokenAndSecret();
  }, [getTokenAndSecret]);

  const getKey = (secret: string) => {
    return CryptoJS.SHA256(secret).toString(CryptoJS.enc.Hex).slice(0, 64); // 32 bytes for AES-256
  };

  const encryptData = (data: string) => {
    if (!secret || !id) {
      getTokenAndSecret();
      throw new Error("Missing secret or id. Reconnecting.");
    }

    const key = getKey(secret);
    const iv = id.slice(0, 16); // Use the first 16 bytes of id as IV
    const encryptedData = CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(key), {
      iv: CryptoJS.enc.Hex.parse(iv),
    }).toString();

    return encryptedData;
  };

  const generateHMAC = (encryptedData: string) => {
    if (!secret) {
      getTokenAndSecret();
      throw new Error("Missing secret. Reconnecting.");
    }

    return CryptoJS.HmacSHA256(encryptedData, secret).toString();
  };

  const decryptData = (encryptedData: string) => {
    if (!secret || !id) {
      getTokenAndSecret();
      throw new Error("Missing secret or id. Reconnecting.");
    }

    const key = getKey(secret);
    const iv = id.slice(0, 16);
    const bytes = CryptoJS.AES.decrypt(encryptedData, CryptoJS.enc.Hex.parse(key), {
      iv: CryptoJS.enc.Hex.parse(iv),
    });
    const decryptedData = bytes.toString(CryptoJS.enc.Utf8);
    return decryptedData;
  };

  const saveData = async () => {
    if (!data) {
      showToast("No data to save.");
      return;
    }

    try {
      const encryptedData = encryptData(data);
      const hmac = generateHMAC(encryptedData);

      await fetch(`${API_URL}/`, {
        method: "POST",
        body: JSON.stringify({ data: encryptedData, hmac }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        credentials: "include",
      });

      showToast("Data saved successfully.");
    } catch (error) {
      showToast("Error saving data.");
      console.error("Error saving data:", error);
    }
  };

  const retrieveData = async () => {
    try {
      const response = await fetch(`${API_URL}/`, {
        credentials: "include",
      });
      const result = await response.json();
      const { encryptedData, hmac } = result.data;

      const calculatedHmac = generateHMAC(encryptedData);
      if (calculatedHmac !== hmac) {
        showToast("Data integrity compromised.");
        return;
      }

      const decryptedData = decryptData(encryptedData);
      setData(decryptedData);
      showToast("Data retrieved and decrypted successfully.");
    } catch (error) {
      showToast("Error retrieving data.");
      console.error("Error retrieving data:", error);
    }
  };

  const clearSecret = () => {
    setId(null)
    setSecret(null)
  }

  return (
    <div
      style={{
        width: "100vw",
        height: "100vh",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        flexDirection: "column",
        gap: "20px",
        fontSize: "30px",
      }}
    >
      <div>Encrypted & Secure Data Management</div>
      <input
        style={{ fontSize: "30px" }}
        type="text"
        value={data}
        onChange={(e) => setData(e.target.value)}
      />

      <div style={{ display: "flex", gap: "10px" }}>
        <button style={{ fontSize: "20px" }} onClick={saveData}>
          Save Data
        </button>
        <button style={{ fontSize: "20px" }} onClick={retrieveData}>
          Retrieve Data
        </button>
        <button style={{ fontSize: "20px" }} onClick={clearSecret}>
          Clear Secret
        </button>
      </div>
    </div>
  );
}

export default App;
