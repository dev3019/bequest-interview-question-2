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

  const getTokenAndSecret = useCallback(async (retries=3) => {
    try {
      const response = await fetch(`${API_URL}/connect`, {
        credentials: "include",
      });
      const data = await response.json();
      setId(data.data.id);
      setSecret(data.data.secret);
      showToast("Connected successfully, secret retrieved.");
    } catch (error) {
      if (retries > 0) {
        setTimeout(() => getTokenAndSecret(retries - 1), 1000);
      } else {
        showToast("Error connecting to API after multiple attempts.");
        console.error("Error connecting to API:", error);
      }
    }
  }, []);

  useEffect(() => {
    getTokenAndSecret();
  }, [getTokenAndSecret]);

  const getKey = (secret: string) => {
    return CryptoJS.SHA256(secret).toString(CryptoJS.enc.Hex).slice(0, 64); // 32 bytes for AES-256
  };

  const encryptData = async(data: string) => {
    if (!secret || !id) {
      await getTokenAndSecret();
      throw new Error("Missing secret or id. Reconnecting.");
    }

    const key = getKey(secret);
    const iv = id.slice(0, 16); // Use the first 16 bytes of id as IV
    const encryptedData = CryptoJS.AES.encrypt(data, CryptoJS.enc.Hex.parse(key), {
      iv: CryptoJS.enc.Hex.parse(iv),
    }).toString();

    return encryptedData;
  };

  const generateHMAC = async(encryptedData: string) => {
    if (!secret) {
      await getTokenAndSecret();
      throw new Error("Missing secret. Reconnecting.");
    }

    return CryptoJS.HmacSHA256(encryptedData, secret).toString();
  };

  const decryptData = async (encryptedData: string) => {
    if (!secret || !id) {
      await getTokenAndSecret();
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
      const encryptedData = await encryptData(data);
      const hmac = await generateHMAC(encryptedData);

      const response = await fetch(`${API_URL}/`, {
        method: "POST",
        body: JSON.stringify({ data: encryptedData, hmac }),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        credentials: "include",
      });

      const result = await response.json();

      // Handle different error cases from the server
      if (response.status === 400) {
        if (result.message === "Bad Request.") {
          showToast("Bad Request. Please reconnect.");
        } else if (result.message === "Secret missing, please connect again.") {
          showToast("Secret missing. Please reconnect.");
          clearSecret(); // Clear the secret and id on client-side
          await getTokenAndSecret(); // Attempt to reconnect and fetch the secret
        } else if (result.message === "Data integrity compromised.") {
          showToast("Data integrity compromised. Please try again.");
        }
      } else if (response.status === 200) {
        showToast("Data saved successfully.");
      } else {
        showToast("Error: Unexpected response from the server.");
      }
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

      if (!response.ok) {
        const errorMessage = await response.json();
        if(response.status===400){
          if (errorMessage.message === "Bad Request.") {
            showToast("Bad request: Please connect again.");
            await getTokenAndSecret(); // Try reconnecting to get a new secret
          } else if (errorMessage.message === "Secret missing, please connect again.") {
            showToast("Secret is missing: Please connect again.");
            await getTokenAndSecret(); // Reconnect to get the secret
          } else if (errorMessage.message.includes("backup missing")) {
            showToast("Data tampered and backup missing: Please connect and save data again.");
            await clearSecret(); // Clear the data as it's compromised
          }
        }
        return;
      }


      const result = await response.json();
      const { encryptedData, hmac } = result.data;

      const calculatedHmac = await generateHMAC(encryptedData);
      if (calculatedHmac !== hmac) {
        showToast("Data integrity compromised in-transit.");
        return;
      }

      const decryptedData = await decryptData(encryptedData);
      setData(decryptedData);
      showToast("Data retrieved and decrypted successfully.");
    } catch (error) {
      showToast("Error retrieving data.");
      console.error("Error retrieving data:", error);
    }
  };

  const clearSecret = async() => {
    setId(null)
    setSecret(null)
    await getTokenAndSecret()
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
