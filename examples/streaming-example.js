const axios = require("axios");
const { LightstreamerClient, Subscription } = require("lightstreamer-client");
const pidCrypt = require("pidcrypt");
const IG_API_URL = "https://demo-api.ig.com/gateway/deal";
const IG_API_KEY = "";
const IG_USERNAME = "";
const IG_PASSWORD = "";
const ATR_PERIOD = 10;
const SUPER_TREND_MULTIPLIER = 3;
const pastResult = [];
const pastSuperTrend = [];

let lastSentTrend;
let supertrend;

const { calculateSupertrend } = require("../src/indicators/supertrend");
// Removed RSI import as it's no longer needed

require("pidcrypt/rsa");
require("pidcrypt/asn1");

// Function to encrypt the password using RSA with OAEP padding
function _pwdEncrypter(password, encryptionKey, timestamp) {
  let rsa = new pidCrypt.RSA();
  let decodedKey = pidCryptUtil.decodeBase64(encryptionKey);
  let asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(decodedKey));
  let tree = asn.toHexTree();
  rsa.setPublicKeyFromASN(tree);
  const result = pidCryptUtil.encodeBase64(
    pidCryptUtil.convertFromHex(rsa.encrypt(password + "|" + timestamp)));

  return result;
}

// Function to obtain the encryption key
async function getEncryptionKey() {
  try {
    const response = await axios.get(`${IG_API_URL}/session/encryptionKey`, {
      headers: {
        "Content-Type": "application/json",
        "X-IG-API-KEY": IG_API_KEY,
      },
    });
    const { encryptionKey, timeStamp } = response.data;
    return { encryptionKey, timeStamp };
  } catch (error) {
    console.error(
      "Error obtaining the encryption key:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

// Function to obtain session tokens
async function getSessionTokens() {
  try {
    const { encryptionKey, timeStamp } = await getEncryptionKey();
    const encryptedPassword = _pwdEncrypter(IG_PASSWORD, encryptionKey, timeStamp);

    const response = await axios.post(
      `${IG_API_URL}/session`,
      {
        identifier: IG_USERNAME,
        password: encryptedPassword,
        encryptedPassword: true,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Version: "2",
          "X-IG-API-KEY": IG_API_KEY,
        },
      }
    );

    const { lightstreamerEndpoint } = response.data;

    return {
      CST: response.headers.cst,
      X_SECURITY_TOKEN: response.headers["x-security-token"],
      LS_ENDPOINT: lightstreamerEndpoint,
    };
  } catch (error) {
    console.error(
      "Error obtaining session tokens:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

// Function to connect to Lightstreamer and subscribe to market prices
function connectToStreaming(tokens) {
  const lsClient = new LightstreamerClient(tokens.LS_ENDPOINT);

  lsClient.connectionDetails.setUser("Z5U9VN");
  lsClient.connectionDetails.setPassword(
    `CST-${tokens.CST}|XST-${tokens.X_SECURITY_TOKEN}`
  );

  lsClient.addListener({
    onListenStart: () => {
      console.log("ListenStart");
    },
    onStatusChange: (status) => {
      console.log("Connection status:", status);
    },
  });

  lsClient.connect();

  // Define the items and fields to subscribe to
  const items = ["CHART:CS.D.EURUSD.CSD.IP:1MINUTE"];
  const fields = [
    "BID_OPEN",
    "BID_CLOSE",
    "BID_LOW",
    "BID_HIGH",
    "UTM",
    "CONS_END",
  ];

  // Change subscription mode from "DISTINCT" to "MERGE"
  const subscription = new Subscription("MERGE", items, fields);
  subscription.setRequestedMaxFrequency(0.5);

  subscription.addListener({
    onSubscription: () => {
      console.log("Subscribed to market prices");
    },
    onUnsubscription: () => {
      console.log("Unsubscribed from market prices");
    },
    onSubscriptionError: (code, message) => {
      console.error(`Subscription error: ${code} - ${message}`);
    },
    onItemUpdate: (updateInfo) => {
      const item = updateInfo.getItemName();
      const bidOpen = parseFloat(updateInfo.getValue("BID_OPEN"));
      const bidClose = parseFloat(updateInfo.getValue("BID_CLOSE"));
      const bidLow = parseFloat(updateInfo.getValue("BID_LOW"));
      const bidHigh = parseFloat(updateInfo.getValue("BID_HIGH"));
      const utm = new Date(Number(updateInfo.getValue("UTM"))).toLocaleString();
      const candleEnd = updateInfo.getValue("CONS_END") === "1";

      console.log("raw utm", updateInfo.getValue("UTM"));
      console.log("utm", utm);
      console.log("candleEnd", candleEnd);
      if (candleEnd) {
        console.log(
          `Update time ${utm} for ${item}: BID_OPEN = ${bidOpen}, BID_CLOSE = ${bidClose}, BID_LOW = ${bidLow} BID_HIGH = ${bidHigh}`
        );
        pastResult.push({
          o: bidOpen,
          h: bidHigh,
          l: bidLow,
          c: bidClose,
        });

        supertrend = calculateSupertrend(
          pastResult,
          ATR_PERIOD,
          SUPER_TREND_MULTIPLIER
        );

        console.log("Updated supertrend: ", supertrend);

        // Determine current trend
        const lastSupertrend = supertrend[supertrend.length - 1];
        const lastClose = pastResult[pastResult.length - 1].c;
        let currentTrend = null;

        if (lastSupertrend !== null && lastSupertrend !== undefined) {
          currentTrend = lastClose > lastSupertrend ? "Uptrend" : "Downtrend";
        } else {
          currentTrend = "Uptrend"; // Default to Uptrend if Supertrend is not available
        }

        console.log("Current trend based on supertrend: ", currentTrend);

        // Check for trend change
        if (currentTrend !== lastSentTrend) {
          // Create a new trade
          const newTradeAction = currentTrend === "Uptrend" ? "BUY" : "SELL";
          const newTrade = {
            action: newTradeAction,
            entryPrice: lastClose,
            status: "open",
            entryTime: new Date(),
          };

          console.log(`New trade created: ${JSON.stringify(newTrade)}`);
          lastSentTrend = currentTrend;
        }
      }

      // Add your logic here to handle live price updates
    },
  });

  lsClient.subscribe(subscription);
}

async function fetchHistoricalData(tokens) {
  try {
    const response = await axios.get(
      `${IG_API_URL}/prices/CS.D.EURUSD.CSD.IP`,
      {
        params: {
          max: 100, // Fetch the most recent 100 candlesticks
          pageSize: 100,
          resolution: "MINUTE",
        },
        headers: {
          "Content-Type": "application/json",
          "X-IG-API-KEY": IG_API_KEY,
          CST: tokens.CST,
          Version: 3,
          "X-SECURITY-TOKEN": tokens.X_SECURITY_TOKEN,
        },
      }
    );

    const historicalData = response.data.prices.map((price) => ({
      o: price.openPrice.bid,
      c: price.closePrice.bid,
      l: price.lowPrice.bid,
      h: price.highPrice.bid,
      t: new Date(price.snapshotTimeUTC).toLocaleString(),
    }));

    pastResult.push(...historicalData);
    console.log("Fetched historical data:", historicalData);

    return historicalData;
  } catch (error) {
    console.error(
      "Error fetching historical data:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

// Main function to initialize streaming and fetch historical data
(async () => {
  try {
    const tokens = await getSessionTokens();
    const historicalData = await fetchHistoricalData(tokens);

    supertrend = calculateSupertrend(
      historicalData,
      ATR_PERIOD,
      SUPER_TREND_MULTIPLIER
    );

    pastSuperTrend.push(...supertrend);
    console.log('historicalData:', historicalData)
    console.log("Initial supertrend: ", supertrend);

    if (historicalData.length > 0 && pastSuperTrend.length > 0) {
      lastSentTrend = historicalData[historicalData.length - 1].c > pastSuperTrend[pastSuperTrend.length - 1] ? "Uptrend" : "Downtrend";
    }

    connectToStreaming(tokens);
  } catch (error) {
    console.error("Error initializing streaming:", error.message);
    process.exit(1);
  }
})();
