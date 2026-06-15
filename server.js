const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs'); // Added to resolve Render secret path variations safely

const app = express(); 
const PORT = 5000;

// 1. Your Google Sheet ID
const SPREADSHEET_ID = "1-JzWpjp7srwoMJcEmJ7PCbrdCGu467pQYow2_YJteE0";

// Middleware
app.use(cors());
app.use(express.json());

// Defensive path lookup to handle local subfolder execution vs Render root secret file injection
let credentialsPath = path.join(__dirname, "credentials.json");
if (!fs.existsSync(credentialsPath) && fs.existsSync(path.join(process.cwd(), "credentials.json"))) {
  credentialsPath = path.join(process.cwd(), "credentials.json");
}

// 2. Set up the Google Auth connection using bulletproof paths
const auth = new google.auth.GoogleAuth({
  keyFile: credentialsPath, 
  scopes: "https://www.googleapis.com/auth/spreadsheets", 
});

// SAFE UTILITY: Strips out Google Sheets formatting commas before parsing to prevent number truncation
const cleanParseFloat = (val) => {
  if (val === undefined || val === null) return 0;
  const cleaned = String(val).replace(/,/g, '');
  const parsed = parseFloat(cleaned);
  return isNaN(parsed) ? 0 : parsed;
};

app.get('/', (req, res) => {
  res.send('Backend server is running!');
});


// ==========================================
// REGISTRATION ENDPOINT (9-COLUMN COMPLIANT SCHEMA)
// ==========================================
app.post('/api/register', async (req, res) => {
  // Defensive fallbacks to accept either username or email property variations safely
  const username = req.body.username || req.body.email;
  const { password, nameOfUser, userType, department, contactNumber } = req.body;

  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    // Query column A specifically to check for duplicates safely in Sheet1
    const getRows = await googleSheets.spreadsheets.values.get({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "Sheet1!A:A",
    });

    const rows = getRows.data.values || [];
    const dataRows = rows.slice(1);
    const userExists = dataRows.some(row => row[0] && row[0].toString().trim().toLowerCase() === String(username).trim().toLowerCase());

    if (userExists) {
      return res.status(400).json({ message: "Email address username already exists in portal registry." });
    }

    // Hash the password cleanly via bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to "Sheet1" using your exact 9-column header layout arrangement order
    const newUserRecordRow = [[
      username,                   // Col A: Email
      hashedPassword,             // Col B: Password
      nameOfUser || '',           // Col C: Name of User
      userType || '',             // Col D: User Type
      department || '',           // Col E: Department
      nameOfUser || '',           // Col F: Name of End User (Automatically defaults to Name of User)
      contactNumber || '',        // Col G: Contact Number
      new Date().toLocaleString(),// Col H: Timestamp
      'Pending'                   // Col I: Status (Stamps as Pending for Admin Approval Gateway Desk)
    ]];

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "Sheet1!A:I", // Appending across all 9 data columns cleanly
      valueInputOption: "USER_ENTERED",
      resource: { values: newUserRecordRow },
    });

    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Account registration internal crash:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});


// ==========================================
// LOGIN ENDPOINT (BOUNDED RANGE SAFETY CHECK)
// ==========================================
app.post('/api/login', async (req, res) => {
  // Defensive fallbacks to accept either username or email property variations safely
  const username = req.body.username || req.body.email;
  const { password } = req.body;

  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    // Fetch bounding columns A:I safely from Sheet1 to read structural status parameters
    const getRows = await googleSheets.spreadsheets.values.get({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "Sheet1!A:I",
    });

    const rows = getRows.data.values || [];
    const dataRows = rows.slice(1);
    const userRow = dataRows.find(row => row[0] && row[0].toString().trim().toLowerCase() === String(username).trim().toLowerCase());

    if (!userRow) {
      return res.status(400).json({ message: "Invalid username or password configuration." });
    }

    // De-structure baseline parameters from rows securely including Column I status indicators
    const [storedUsername, storedHashedPassword, nameOfUser, userType, department, , contactNumber, , status] = userRow;

    // Safety Intercept Check: Prevent bcrypt from crashing on missing, empty, or unencrypted cell entries
    if (!storedHashedPassword || typeof storedHashedPassword !== 'string' || !storedHashedPassword.startsWith('$2')) {
      return res.status(400).json({ message: "Account profile found, but password hash structure inside column grid is blank or corrupt." });
    }

    // Compare passwords securely using bcrypt engine hashes
    const isPasswordValid = await bcrypt.compare(password, storedHashedPassword);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid username or password configuration." });
    }

    // Successful login response
    res.status(200).json({
      message: "Login successful!",
      user: { 
        username: storedUsername, 
        department, 
        userType,
        nameOfUser,
        contactNumber: contactNumber || '',
        status: status || 'Pending'
      },
    });
  } catch (error) {
    console.error("Login verification checkpoint crashed:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// ==========================================
// ACCOUNTS MANAGEMENT SYSTEM ENDPOINTS
// ==========================================

// 1. GET ALL REGISTERED ACCOUNT USERS
app.get('/api/users', async (req, res) => {
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    // Expanded range to A:I to collect Status parameters safely
    const getRows = await googleSheets.spreadsheets.values.get({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "Sheet1!A:I",
    });

    const rows = getRows.data.values || [];
    
    // Skip header row if it exists, map clean records back
    const formattedUsers = rows.slice(1).map((row, index) => ({
      id: index + 2, 
      username: row[0] || '',
      nameOfUser: row[2] || '',
      userType: row[3] || '',
      department: row[4] || '',
      contactNumber: row[6] || '',
      timestamp: row[7] || '',
      status: row[8] || 'Pending' // Column I maps directly here
    }));

    res.status(200).json(formattedUsers);
  } catch (error) {
    console.error("Failed to load user accounts ledger map profile context:", error);
    res.status(500).json({ message: "Database lookup failure." });
  }
});

// 2. FORCE OVERRIDE UPDATE EXECUTING ON USER ACCOUNT
app.post('/api/users/update', async (req, res) => {
  // Advanced Payload Intercept: Unpacks properties regardless of root or nested frontend object casing variations
  const originalUsername = req.body.originalUsername || req.body.username || req.body.email || 
                           (req.body.updatedUser && (req.body.updatedUser.username || req.body.updatedUser.email));
  
  const updatedUser = req.body.updatedUser || req.body;
  const statusUpdate = req.body.status || updatedUser.status;

  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const getRows = await googleSheets.spreadsheets.values.get({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "Sheet1!A:I",
    });
    const rows = getRows.data.values || [];
    
    // Robust case-insensitive comparison loop to neutralize whitespace variances
    let sheetTargetLineIndex = -1;
    for(let i = 0; i < rows.length; i++) {
      if (rows[i][0] && originalUsername && rows[i][0].toString().trim().toLowerCase() === originalUsername.toString().trim().toLowerCase()) {
        sheetTargetLineIndex = i + 1; 
        break;
      }
    }

    if (sheetTargetLineIndex === -1) {
      return res.status(404).json({ 
        message: `Target identifier [${originalUsername}] was not found inside Column A of Sheet1.`
      });
    }

    const existingRow = rows[sheetTargetLineIndex - 1];

    // Compile values block array matching schema adjustments across all 9 data columns securely
    const cellValuePayload = [
      originalUsername || existingRow[0] || '',                  // Col A: Email
      updatedUser.password || existingRow[1] || '',               // Col B: Password Hash
      updatedUser.nameOfUser || existingRow[2] || '',             // Col C: Name of User
      updatedUser.userType || existingRow[3] || '',               // Col D: User Type
      updatedUser.department || existingRow[4] || '',             // Col E: Department Office
      updatedUser.nameOfUser || existingRow[5] || existingRow[2] || '', // Col F: Name of End User
      updatedUser.contactNumber || existingRow[6] || '',         // Col G: Contact Number
      existingRow[7] || new Date().toLocaleString(),               // Col H: Timestamp
      statusUpdate || existingRow[8] || 'Pending'                 // Col I: Overwrites target status cells flawlessly
    ];

    await googleSheets.spreadsheets.values.update({
      auth, spreadsheetId: SPREADSHEET_ID,
      range: `Sheet1!A${sheetTargetLineIndex}:I${sheetTargetLineIndex}`, // Target complete row width
      valueInputOption: "USER_ENTERED",
      resource: { values: [cellValuePayload] }
    });

    res.status(200).json({ message: "Account profile successfully overwritten inside data stream mapping registry." });
  } catch (error) {
    console.error("User status modification crash error details:", error);
    res.status(500).json({ message: "Failed to push network write action to user record sheet." });
  }
});

// 3. DROPS TARGET USER ACCOUNT PERMANENTLY FROM DIRECTORY
app.post('/api/users/delete', async (req, res) => {
  const { username } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const getRows = await googleSheets.spreadsheets.values.get({
      auth, spreadsheetId: SPREADSHEET_ID, range: "Sheet1!A:A"
    });
    const rows = getRows.data.values || [];

    let targetDeleteLineIndex = -1;
    for(let i=0; i<rows.length; i++) {
      if(rows[i][0] === username) {
        targetDeleteLineIndex = i; 
        break;
      }
    }

    if(targetDeleteLineIndex === -1) return res.status(404).json({ message: "Account context pointer not found." });

    const meta = await googleSheets.spreadsheets.get({ spreadsheetId: SPREADSHEET_ID });
    const sheetId = meta.data.sheets.find(s => s.properties.title === "Sheet1")?.properties.sheetId;

    await googleSheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID,
      resource: {
        requests: [{
          deleteDimension: {
            range: { sheetId: sheetId, dimension: "ROWS", startIndex: targetDeleteLineIndex, endIndex: targetDeleteLineIndex + 1 }
          }
        }]
      }
    });

    res.status(200).json({ message: "User securely disconnected from directory schema." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Critical authorization intercept failure on deletion process script." });
  }
});


// ==========================================
// LDIP LEDGER ENDPOINTS
// ==========================================
app.post('/api/ldip', async (req, res) => {
  const { office, sectorCode, sectorName, title, description, targets, budget } = req.body;

  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const timestamp = new Date().toLocaleString();
    const targetsArray = Array.isArray(targets) ? targets : (targets ? [targets] : []);

    // Append entry to "LDIP" sheet
    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "LDIP!A:H",
      valueInputOption: "USER_ENTERED",
      resource: {
        values: [[office, sectorCode, sectorName, title, description, targetsArray.join(', '), budget, timestamp]],
      },
    });

    res.status(201).json({ message: "LDIP entry saved successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.get('/api/ldip/:department', async (req, res) => {
  const { department } = req.params;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "LDIP!A:H" });
    const rows = response.data.values;

    if (!rows || rows.length <= 1) return res.status(200).json([]);

    const cleanDept = String(department).trim().toLowerCase();

    const filteredEntries = rows.slice(1)
      .filter(row => {
        if (!row || !row[0]) return false;
        if (cleanDept === 'all') return true;
        return row[0].toString().trim().toLowerCase() === cleanDept;
      })
      .map((row, index) => ({
        id: index,
        office: row[0] || 'Unknown',
        sectorCode: row[1] || '0000',
        sectorName: row[2] || 'Unassigned',
        title: row[3] || 'Untitled Program',
        description: row[4] || '',
        targets: (row[5] !== undefined && row[5] !== null) ? String(row[5]).split(', ') : [], 
        budget: cleanParseFloat(row[6]), 
        timestamp: row[7] || ''
      }));

    res.status(200).json(filteredEntries.reverse());
  } catch (error) {
    console.error("Backend Error in GET /api/ldip/:department:", error);
    res.status(500).json({ message: "Failed to retrieve records from cloud ledger.", error: error.toString() });
  }
});

// LOCAL CONTROL: UPDATE AN EXISTING LDIP ROW ENTRY IN THE SPREADSHEET
app.post('/api/ldip/update', async (req, res) => {
  const { originalOffice, originalTitle, originalTimestamp, updatedEntry } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "LDIP!A:H" });
    const rows = response.data.values || [];

    let targetRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (
        rows[i][0] === originalOffice &&
        rows[i][3] === originalTitle &&
        rows[i][7] === originalTimestamp
      ) {
        targetRowIndex = i + 1; 
        break;
      }
    }

    if (targetRowIndex === -1) return res.status(404).json({ message: "Target LDIP record layout not found." });

    const updatedTargetsArray = Array.isArray(updatedEntry.targets) ? updatedEntry.targets : (updatedEntry.targets ? [updatedEntry.targets] : []);

    const updatedRow = [
      updatedEntry.office,
      updatedEntry.sectorCode,
      updatedEntry.sectorName,
      updatedEntry.title,
      updatedEntry.description,
      updatedTargetsArray.join(', '),
      updatedEntry.budget,
      originalTimestamp 
    ];

    await googleSheets.spreadsheets.values.update({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: `LDIP!A${targetRowIndex}:H${targetRowIndex}`,
      valueInputOption: "USER_ENTERED",
      resource: { values: [updatedRow] }
    });

    res.status(200).json({ message: "LDIP entry updated successfully inside cloud ledger." });
  } catch (error) {
    res.status(500).json({ message: "Failed to update LDIP spreadsheet row." });
  }
});

app.post('/api/ldip/delete', async (req, res) => {
  const { office, title, timestamp } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    
    const response = await googleSheets.spreadsheets.values.get({ 
      auth, 
      spreadsheetId: SPREADSHEET_ID, 
      range: "LDIP!A:H" 
    });
    const rows = response.data.values || [];

    let targetIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] === office && rows[i][3] === title && rows[i][7] === timestamp) {
        targetIndex = i; 
        break;
      }
    }

    if (targetIndex === -1) {
      return res.status(404).json({ message: "Record index coordinates not found in sheet." });
    }

    const meta = await googleSheets.spreadsheets.get({ spreadsheetId: SPREADSHEET_ID });
    const sheetId = meta.data.sheets.find(s => s.properties.title === "LDIP")?.properties.sheetId;

    await googleSheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID,
      resource: {
        requests: [{
          deleteDimension: {
            range: { 
              sheetId: sheetId, 
              dimension: "ROWS", 
              startIndex: targetIndex, 
              endIndex: targetIndex + 1 
            }
          }
        }]
      }
    });

    res.status(200).json({ message: "Success! Row deleted and shifted up locally." });
  } catch (error) {
    console.error("Local Delete Error Details:", error);
    res.status(500).json({ message: "Failed to clear and shift target spreadsheet row locally." });
  }
});


// CORE ROUTE: GENERATES RIGID FORMAT [Office Code]-[Program].[Project].[Activity] CODES FOR ALL ROWS
app.post('/api/ldip/import', async (req, res) => {
  const { office, rows } = req.body;
  try {
    if (!rows || !Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({ message: "No data rows detected in the import package." });
    }

    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    // --- STEP 1: POPULATE GRANULAR ACTIVITIES TO THE LIVE AIP SHEET (AIP!A:R) ---
    const aipRange = 'AIP!A:R';
    const aipRowsToAppend = rows.map(row => {
      const masterOfficePrefix = row.officeCode || '3000-000-3-3-11';
      const generatedRefCode = `${masterOfficePrefix}-${row.programId || '0'}.${row.projectId || '0'}.${row.activityId || '0'}`;

      return [
        generatedRefCode,
        row.office || office || '', 
        row.program || '',
        row.project || '',
        row.activities || 'N/A (Standalone Project)',
        row.office || office || '',
        row.startingDate || '',
        row.completionDate || '',
        row.expectedOutputs || '',
        row.fundingSource || '',
        row.ps || 0,
        row.mooe || 0,
        row.co || 0,
        row.total || 0,
        row.climateAdaptation || 0,
        row.climateMitigation || 0,
        row.ccTypologyCode || '',
        new Date().toLocaleString()
      ];
    });

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: aipRange,
      valueInputOption: "USER_ENTERED",
      resource: { values: aipRowsToAppend },
    });

    // --- STEP 2: AGGREGATE UNIQUE MAIN PROGRAM SLOTS TO LIVE LDIP SHEET (LDIP!A:H) ---
    const ldipCheck = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "LDIP!A:H" });
    const existingLdipRows = ldipCheck.data.values || [];
    const existingTitles = existingLdipRows.slice(1).map(r => r[3] ? r[3].toString().trim().toLowerCase() : '');

    const programAggregationMap = {};
    rows.forEach(row => {
      const titleKey = row.program || 'Untitled Program';
      if (!programAggregationMap[titleKey]) {
        programAggregationMap[titleKey] = {
          office: row.office || office || '',
          sectorCode: row.sectorCode || '0000',
          sectorName: row.sectorName || 'Unassigned',
          title: titleKey,
          description: `Bulk Spreadsheet Imported Allotment Package.`,
          accumulatedBudget: 0
        };
      }
      programAggregationMap[titleKey].accumulatedBudget += parseFloat(row.total) || 0;
    });

    const ldipRowsToAppend = [];
    Object.values(programAggregationMap).forEach(prog => {
      if (!existingTitles.includes(prog.title.trim().toLowerCase())) {
        const compiledYears = '2027, 2028, 2029';
        ldipRowsToAppend.push([
          prog.office, 
          prog.sectorCode,
          prog.sectorName,
          prog.title,
          prog.description,
          compiledYears,
          prog.accumulatedBudget,
          new Date().toLocaleString()
        ]);
      }
    });

    if (ldipRowsToAppend.length > 0) {
      await googleSheets.spreadsheets.values.append({
        auth,
        spreadsheetId: SPREADSHEET_ID,
        range: "LDIP!A:H",
        valueInputOption: "USER_ENTERED",
        resource: { values: ldipRowsToAppend },
      });
    }

    res.status(200).json({ message: "Success! Balanced row sets integrated.", addedCount: rows.length });
  } catch (error) {
    console.error("Integration Matrix Failure Intercept:", error);
    res.status(500).json({ message: "Critical error compiling relational spreadsheets maps pointers data sets." });
  }
});


// ==========================================
// AIP SYSTEM LEDGER ENDPOINTS
// ==========================================
app.post('/api/aip', async (req, res) => {
  const { aipRefCode, office, programTitle, projectName, activityName, startingDate, completionDate, expectedOutput, fundingSource, ps, mooe, co, total } = req.body;

  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const timestamp = new Date().toLocaleString();

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "AIP!A:N",
      valueInputOption: "USER_ENTERED",
      resource: {
        values: [[aipRefCode, office, programTitle, projectName, activityName, startingDate, completionDate, expectedOutput, fundingSource, ps, mooe, co, total, timestamp]],
      },
    });

    res.status(201).json({ message: "AIP item saved successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.get('/api/aip/:department', async (req, res) => {
  const { department } = req.params;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "AIP!A:R" });
    const rows = response.data.values;

    if (!rows || rows.length <= 1) return res.status(200).json([]);

    const cleanDept = String(department).trim().toLowerCase();

    const filteredEntries = rows.slice(1)
      .filter(row => {
        if (!row || !row[1]) return false;
        if (cleanDept === 'all') return true;
        return row[1].toString().trim().toLowerCase() === cleanDept;
      }) 
      .map((row, index) => ({
        id: index,
        aipRefCode: row[0] || 'Uncoded',
        office: row[1] || 'Unknown',
        programTitle: row[2] || '',
        projectName: row[3] || '',
        activityName: row[4] || '',
        implementingOffice: row[5] || '',
        startDate: row[6] || '',
        completionDate: row[7] || '',
        expectedOutput: row[8] || '',
        fundingSource: row[9] || '',
        ps: cleanParseFloat(row[10]),           
        mooe: cleanParseFloat(row[11]),         
        co: cleanParseFloat(row[12]),           
        total: cleanParseFloat(row[13]),        
        ccAdaptation: cleanParseFloat(row[14]), 
        ccMitigation: cleanParseFloat(row[15]), 
        ccTypology: row[16] || '',
        timestamp: row[17] || ''
      }));

    res.status(200).json(filteredEntries.reverse());
  } catch (error) {
    console.error("Backend Error in GET /api/aip/:department:", error);
    res.status(500).json({ message: "Failed to retrieve records from cloud ledger.", error: error.toString() });
  }
});

app.post('/api/aip/update', async (req, res) => {
  const { originalRefCode, updatedEntry } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "AIP!A:R" });
    const rows = response.data.values;

    if (!rows || rows.length === 0) {
      return res.status(404).json({ message: "Database ledger is empty. Please verify baseline rows are imported first." });
    }

    let targetRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] && originalRefCode && rows[i][0].toString().trim().toLowerCase() === originalRefCode.toString().trim().toLowerCase()) {
        targetRowIndex = i + 1;
        break;
      }
    }

    if (targetRowIndex === -1) {
      return res.status(404).json({ message: 'Target AIP reference code row [' + originalRefCode + '] not found in spreadsheet layout.' });
    }

    const updatedValues = [[
      originalRefCode,
      updatedEntry.office,
      updatedEntry.programTitle,
      updatedEntry.projectName,
      updatedEntry.activityName || 'N/A (Standalone Project)',
      updatedEntry.implementingOffice,
      updatedEntry.startDate,
      updatedEntry.completionDate,
      updatedEntry.expectedOutput,
      updatedEntry.fundingSource,
      updatedEntry.ps,
      updatedEntry.mooe,
      updatedEntry.co,
      updatedEntry.total,
      updatedEntry.ccAdaptation,
      updatedEntry.ccMitigation,
      updatedEntry.ccTypology,
      new Date().toLocaleString()
    ]];

    await googleSheets.spreadsheets.values.update({
      auth, spreadsheetId: SPREADSHEET_ID, range: `AIP!A${targetRowIndex}:R${targetRowIndex}`,
      valueInputOption: "USER_ENTERED", resource: { values: [updatedValues] }
    });

    res.status(200).json({ message: "AIP entry updated successfully." });
  } catch (error) {
    console.error("AIP update endpoint crashed:", error);
    res.status(500).json({ message: "Failed to update AIP entry." });
  }
});

app.post('/api/aip/delete', async (req, res) => {
  const { aipRefCode } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    
    const response = await googleSheets.spreadsheets.values.get({ 
      auth, 
      spreadsheetId: SPREADSHEET_ID, 
      range: "AIP!A:A" 
    });
    const rows = response.data.values || [];

    let targetIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] && rows[i][0].toString().trim().toLowerCase() === String(aipRefCode).trim().toLowerCase()) {
        targetIndex = i; 
        break;
      }
    }

    if (targetIndex === -1) {
      return res.status(404).json({ message: "AIP reference code index coordinate not found." });
    }

    const meta = await googleSheets.spreadsheets.get({ spreadsheetId: SPREADSHEET_ID });
    const sheetId = meta.data.sheets.find(s => s.properties.title === "AIP")?.properties.sheetId;

    await googleSheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID,
      resource: {
        requests: [{
          deleteDimension: {
            range: { sheetId: sheetId, dimension: "ROWS", startIndex: targetIndex, endIndex: targetIndex + 1 }
          }
        }]
      }
    });

    res.status(200).json({ message: "Success! Row deleted and shifted up cleanly." });
  } catch (error) {
    console.error("Local AIP Delete Error Details:", error);
    res.status(500).json({ message: "Failed to clear and shift target AIP spreadsheet row locally." });
  }
});


// ==========================================
// ANNUAL BUDGET (LBF NO. 4) CONTROLLERS
// ==========================================
app.post('/api/budget', async (req, res) => {
  const entry = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const newBudgetRow = [[
      entry.aipRefCode || '',           
      entry.office || '',               
      entry.programTitle || '',         
      entry.projectName || '',          
      entry.activityName || '',         
      entry.implementingOffice || '',   
      entry.performanceIndicator || '', 
      entry.targetBudgetYear || '',     
      entry.ps || 0,                   
      entry.mooe || 0,                 
      entry.co || 0,                   
      entry.total || 0,                
      entry.includesProcurement || 'No',  
      new Date().toLocaleString() 
    ]];

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "BudgetForm4!A:N",
      valueInputOption: "USER_ENTERED",
      resource: { values: newBudgetRow }, // FIXED: Passed directly as a 2D array matrix to drop the 3D nesting trap
    });

    res.status(201).json({ message: "Budget allocation logged successfully!" });
  } catch (error) {
    console.error("Budget allocation entry error layout context:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.get('/api/budget/:department', async (req, res) => {
  const { department } = req.params;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "BudgetForm4!A:N" });
    const rows = response.data.values;

    if (!rows || rows.length <= 1) return res.status(200).json([]);

    const cleanDept = String(department).trim().toLowerCase();

    const filteredEntries = rows.slice(1)
      .filter(row => {
        if (!row || !row[1]) return false;
        if (cleanDept === 'all') return true;
        return row[1].toString().trim().toLowerCase() === cleanDept;
      })
      .map((row, index) => ({
        id: index,
        aipRefCode: row[0] || '',
        office: row[1] || '',
        programTitle: row[2] || '',
        projectName: row[3] || '',
        activityName: row[4] || '',
        implementingOffice: row[5] || '',
        performanceIndicator: row[6] || '', 
        targetBudgetYear: row[7] || '',     
        ps: cleanParseFloat(row[8]),            
        mooe: cleanParseFloat(row[9]),          
        co: cleanParseFloat(row[10]),          
        total: cleanParseFloat(row[11]),         
        includesProcurement: row[12] || 'No', 
        timestamp: row[13] || ''              
      }));

    res.status(200).json(filteredEntries.reverse());
  } catch (error) {
    console.error("Error fetching Form 4 budget ledger rows:", error);
    res.status(500).json({ message: "Failed to read data matrix from spreadsheet.", error: error.toString() });
  }
});

app.post('/api/budget/update', async (req, res) => {
  const { originalRefCode, updatedEntry } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    
    const response = await googleSheets.spreadsheets.values.get({ 
      auth, spreadsheetId: SPREADSHEET_ID, range: "BudgetForm4!A:N" 
    });
    const rows = response.data.values || [];

    let targetRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] && originalRefCode && rows[i][0].toString().trim().toLowerCase() === originalRefCode.toString().trim().toLowerCase()) {
        targetRowIndex = i + 1; 
        break;
      }
    }

    if (targetRowIndex === -1) {
      return res.status(404).json({ message: `Target budget row reference [${originalRefCode}] could not be found.` });
    }

    const updatedRow = [
      originalRefCode,
      updatedEntry.office,
      updatedEntry.programTitle,
      updatedEntry.projectName,
      updatedEntry.activityName,
      updatedEntry.implementingOffice,
      updatedEntry.performanceIndicator,
      updatedEntry.targetBudgetYear,
      updatedEntry.ps,
      updatedEntry.mooe,
      updatedEntry.co,
      updatedEntry.total,
      updatedEntry.includesProcurement,
      new Date().toLocaleString()
    ];

    await googleSheets.spreadsheets.values.update({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: `BudgetForm4!A${targetRowIndex}:N${targetRowIndex}`,
      valueInputOption: "USER_ENTERED",
      resource: { values: [updatedRow] }
    });

    res.status(200).json({ message: "Budget matrix coordinates updated successfully inside Google Sheets cells." });
  } catch (error) {
    console.error("Budget update error:", error);
    res.status(500).json({ message: "Failed to modify database budget cell parameters." });
  }
});

app.post('/api/budget/delete', async (req, res) => {
  const { aipRefCode } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    
    const response = await googleSheets.spreadsheets.values.get({ 
      auth, spreadsheetId: SPREADSHEET_ID, range: "BudgetForm4!A:A" 
    });
    const rows = response.data.values || [];

    let targetIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] && rows[i][0].toString().trim().toLowerCase() === String(aipRefCode).trim().toLowerCase()) {
        targetIndex = i; 
        break;
      }
    }

    if (targetIndex === -1) {
      return res.status(404).json({ message: "Budget record row allocation reference context not found." });
    }

    const meta = await googleSheets.spreadsheets.get({ spreadsheetId: SPREADSHEET_ID });
    const sheetId = meta.data.sheets.find(s => s.properties.title === "BudgetForm4")?.properties.sheetId;

    await googleSheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID,
      resource: {
        requests: [{
          deleteDimension: {
            range: { 
              sheetId: sheetId, 
              dimension: "ROWS", 
              startIndex: targetIndex, 
              endIndex: targetIndex + 1 
            }
          }
        }]
      }
    });

    res.status(200).json({ message: "Success! Row dropped and shifted up cleanly inside budget worksheet." });
  } catch (error) {
    console.error("Local Budget Delete Error:", error);
    res.status(500).json({ message: "Failed to truncate and shift target budget cell row parameters." });
  }
});


// ==========================================
// RIGID FIXED ROW MATRIX PPMP CONTROLLERS
// ==========================================
app.post('/api/ppmp', async (req, res) => {
  const body = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    let rowsToAppend = [];

    // AUTOMATED MATRIX BRANCHING: Dynamically shifts parser context based on incoming batch array loops vs single manual configs
    if (body.entries && Array.isArray(body.entries)) {
      rowsToAppend = body.entries.map(entry => [
        entry.aipRefCode || entry.code || '',                
        entry.office || '',                    
        entry.generalDescription || entry.description || '',        
        entry.typeOfProject || 'Goods',        
        entry.preProcurementConference || 'No',
        entry.startProcurementMonth || '—',   
        entry.endProcurementMonth || '—',     
        entry.expectedDeliveryMonth || '—',   
        entry.sourceOfFunds || 'General Fund', 
        entry.estimatedBudget || 0,            
        JSON.stringify(entry.items || []),     
        new Date().toLocaleString()            
      ]);
    } else {
      const entry = body;
      rowsToAppend = [[
        entry.aipRefCode || entry.code || '',
        entry.office || '',
        entry.generalDescription || entry.description || '',
        entry.typeOfProject || 'Goods',
        entry.preProcurementConference || 'No',
        entry.startProcurementMonth || 'January',
        entry.endProcurementMonth || 'December',
        entry.expectedDeliveryMonth || 'December',
        entry.sourceOfFunds || 'General Fund',
        entry.estimatedBudget || 0,
        JSON.stringify(entry.items || []),
        new Date().toLocaleString()
      ]];
    }

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "PPMP!A:L", 
      valueInputOption: "USER_ENTERED",
      resource: { values: rowsToAppend },
    });

    res.status(200).json({ message: "PPMP item(s) logged successfully!" });
  } catch (error) {
    console.error("PPMP form submission server exception loop catch:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.post('/api/ppmp/update', async (req, res) => {
  const { originalCode, updatedRow } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "PPMP!A:A" });
    const rows = response.data.values || [];

    let matchIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] === originalCode) {
        matchIndex = i + 1; 
        break;
      }
    }
    if (matchIndex === -1) return res.status(404).json({ message: "Target PPMP item pointer lost." });

    const updatedDataPayload = [
      originalCode,                                 
      updatedRow.office,                            
      updatedRow.generalDescription || updatedRow.description || '',          
      updatedRow.typeOfProject || 'Goods',          
      updatedRow.preProcurementConference || 'No',  
      updatedRow.startProcurementMonth || 'January',
      updatedRow.endProcurementMonth || 'December',  
      updatedRow.expectedDeliveryMonth || 'December',
      updatedRow.sourceOfFunds || 'General Fund',   
      updatedRow.estimatedBudget || 0,              
      JSON.stringify(updatedRow.items || []),       
      new Date().toLocaleString()                   
    ];

    await googleSheets.spreadsheets.values.update({
      auth, spreadsheetId: SPREADSHEET_ID, range: `PPMP!A${matchIndex}:L${matchIndex}`,
      valueInputOption: "USER_ENTERED", resource: { values: [updatedDataPayload] }
    });
    res.status(200).json({ message: "PPMP item overwritten inside cells successfully." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to update spreadsheet matrix cells." });
  }
});

app.post('/api/ppmp/delete', async (req, res) => {
  const { code } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    
    const response = await googleSheets.spreadsheets.values.get({ 
      auth, spreadsheetId: SPREADSHEET_ID, range: "PPMP!A:A" 
    });
    const rows = response.data.values || [];

    let targetIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] && rows[i][0].toString().trim().toLowerCase() === String(code).trim().toLowerCase()) {
        targetIndex = i; 
        break;
      }
    }

    if (targetIndex === -1) {
      return res.status(404).json({ message: "PPMP reference context not found." });
    }

    const meta = await googleSheets.spreadsheets.get({ spreadsheetId: SPREADSHEET_ID });
    const sheetId = meta.data.sheets.find(s => s.properties.title === "PPMP")?.properties.sheetId;

    await googleSheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID,
      resource: {
        requests: [{
          deleteDimension: {
            range: { sheetId: sheetId, dimension: "ROWS", startIndex: targetIndex, endIndex: targetIndex + 1 }
          }
        }]
      }
    });

    res.status(200).json({ message: "Success! Row deleted and shifted up cleanly." });
  } catch (error) {
    console.error("Local PPMP Delete Error:", error);
    res.status(500).json({ message: "Failed to delete target PPMP cell row parameters." });
  }
});

app.get('/api/ppmp/:department', async (req, res) => {
  const { department } = req.params;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const response = await googleSheets.spreadsheets.values.get({
      auth, spreadsheetId: SPREADSHEET_ID, range: "PPMP!A:L", 
    });

    const rows = response.data.values || [];
    const cleanDept = String(department).trim().toLowerCase();

    const filteredPpmp = rows.slice(1)
      .filter(row => {
        if (!row || !row[1]) return false;
        if (cleanDept === 'all') return true; // Safety override bypass to support BAC Secretary consolidated metrics view loops
        return row[1].toString().trim().toLowerCase() === cleanDept;
      })
      .map(row => {
        let parsedItems = [];
        try {
          if (row[10]) parsedItems = JSON.parse(row[10]);
        } catch (e) { parsedItems = []; }

        return {
          aipRefCode: row[0] || 'Uncoded',
          office: row[1] || '',
          generalDescription: row[2] || '',
          typeOfProject: row[3] || 'Goods',
          preProcurementConference: row[4] || 'No',
          startProcurementMonth: row[5] || '—',
          endProcurementMonth: row[6] || '—',
          expectedDeliveryMonth: row[7] || '—',
          sourceOfFunds: row[8] || 'General Fund',
          estimatedBudget: cleanParseFloat(row[9]),
          items: parsedItems,
          timestamp: row[11] || ''
        };
      });

    res.status(200).json(filteredPpmp.reverse());
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to read data from PPMP log tracking worksheet cells." });
  }
});


// ==========================================
// APP ENDPOINTS
// ==========================================
app.post('/api/app', async (req, res) => {
  const { appCode, office, procurementProgram, mof, sourceOfFunds, ps, mooe, co, total } = req.body;

  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const timestamp = new Date().toLocaleString();

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "APP!A:J",
      valueInputOption: "USER_ENTERED",
      resource: {
        values: [[appCode, office, procurementProgram, mof, sourceOfFunds, ps, mooe, co, total, timestamp]],
      },
    });

    res.status(201).json({ message: "APP item saved successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.get('/api/app', async (req, res) => {
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const getRows = await googleSheets.spreadsheets.values.get({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "APP!A:J",
    });

    const rows = getRows.data.values || [];

    const formattedApp = rows.slice(1).map(row => ({
      appCode: row[0] || '',
      office: row[1] || '',
      procurementProgram: row[2] || '',
      moof: row[3] || '',
      sourceOfFunds: row[4] || '',
      ps: cleanParseFloat(row[5]),
      mooe: cleanParseFloat(row[6]),
      co: cleanParseFloat(row[7]),
      total: cleanParseFloat(row[8]),
      timestamp: row[9] || ''
    }));

    res.status(200).json(formattedApp.reverse());
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to read data lines from Master APP aggregate worksheet cells log tracker." });
  }
});


// ==========================================
// DASHBOARD STATS AGGREGATION ENDPOINT
// ==========================================
app.get('/api/dashboard/stats/:department', async (req, res) => {
  const { department } = req.params;
  const dClean = department ? department.trim().toLowerCase() : '';

  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const rangesToPull = ["LDIP!A:G", "AIP!A:N", "BudgetForm4!A:L", "PPMP!A:F"];
    const batchDataResponse = await googleSheets.spreadsheets.values.batchGet({
      spreadsheetId: SPREADSHEET_ID, ranges: rangesToPull
    });

    const valueRanges = batchDataResponse.data.valueRanges || [];
    const ldipRows = valueRanges[0]?.values || [];
    const aipRows = valueRanges[1]?.values || [];
    const budgetRows = valueRanges[2]?.values || [];
    const ppmpRows = valueRanges[3]?.values || [];

    const filteredLdip = ldipRows.slice(1).filter(r => !r[0] || dClean === 'all' || r[0].toString().trim().toLowerCase() === dClean);
    const ldipCount = filteredLdip.length;
    const ldipTotal = filteredLdip.reduce((acc, curr) => acc + cleanParseFloat(curr[6]), 0);

    const filteredAip = aipRows.slice(1).filter(r => (!r[1] || dClean === 'all' || r[1].toString().trim().toLowerCase() === dClean) && r[4] !== 'PENDING_CONFIG');
    const aipCount = filteredAip.length;
    const aipTotal = filteredAip.reduce((acc, curr) => acc + cleanParseFloat(curr[13]), 0);

    const filteredBudget = budgetRows.slice(1).filter(r => !r[1] || dClean === 'all' || r[1].toString().trim().toLowerCase() === dClean);
    const budgetTotal = budgetRows.slice(1).reduce((acc, curr) => acc + cleanParseFloat(curr[11]), 0);
    const budgetPs = filteredBudget.reduce((acc, curr) => acc + cleanParseFloat(curr[8]), 0);
    const budgetMooe = filteredBudget.reduce((acc, curr) => acc + cleanParseFloat(curr[9]), 0);
    const budgetCo = filteredBudget.reduce((acc, curr) => acc + cleanParseFloat(curr[10]), 0);

    const filteredPpmp = ppmpRows.slice(1).filter(r => !r[1] || dClean === 'all' || r[1].toString().trim().toLowerCase() === dClean);
    const ppmpTotal = filteredPpmp.reduce((acc, curr) => acc + cleanParseFloat(curr[5]), 0);

    res.status(200).json({
      ldipCount, ldipTotal,
      aipCount, aipTotal,
      budgetTotal, budgetPs, budgetMooe, budgetCo,
      ppmpTotal
    });
  } catch (err) {
    console.error("Dashboard calculation aggregation framework crash:", err);
    res.status(500).json({ message: "Aggregation crash error." });
  }
});

app.listen(PORT, () => {
  console.log('Server is listening on https://municipal-budget-backend.onrender.com');
});