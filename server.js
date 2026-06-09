const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const bcrypt = require('bcrypt');

const app = express(); //  FIXED: Removed the rogue assignment typo
const PORT = 5000;

// 1. Your Google Sheet ID
const SPREADSHEET_ID = "1-JzWpjp7srwoMJcEmJ7PCbrdCGu467pQYow2_YJteE0";

// Middleware
app.use(cors());
app.use(express.json());

// 2. Set up the Google Auth connection using your downloaded credentials
const auth = new google.auth.GoogleAuth({
  keyFile: "credentials.json", 
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
// REGISTRATION ENDPOINT
// ==========================================
app.post('/api/register', async (req, res) => {
  const userData = req.body;
  try {
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const newRow = [
      [
        userData.email,
        hashedPassword, 
        userData.nameOfUser,
        userData.userType || 'Regular User', 
        userData.department,
        userData.nameOfEndUser,
        userData.contactNumber,
        new Date().toLocaleString(),
        'Pending' 
      ]
    ];

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "Sheet1", 
      valueInputOption: "USER_ENTERED",
      resource: { values: newRow },
    });

    res.status(200).json({ message: "Registration successful! Mapped into pending administrator verification loop." });
  } catch (error) {
    res.status(500).json({ message: "Failed to save data." });
  }
});


// ==========================================
// LOGIN ENDPOINT
// ==========================================
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "Sheet1!A:I", 
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
      return res.status(401).json({ message: "No users found." });
    }

    let userRow = null;
    let passwordMatches = false;

    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] && rows[i][0].trim().toLowerCase() === email.trim().toLowerCase()) {
        if (!rows[i][1]) break;
        passwordMatches = await bcrypt.compare(password, rows[i][1]);
        if (passwordMatches) userRow = rows[i];
        break; 
      }
    }

    if (!userRow) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    const accountStatus = (userRow[8] || 'Pending').trim().toLowerCase();
    if (accountStatus !== 'approved') {
      if (accountStatus === 'rejected') {
        return res.status(403).json({ message: "Access Denied: Your account registration has been rejected by an administrator." });
      }
      return res.status(403).json({ message: "Access Mapped: Your registration is currently pending administrator review and approval." });
    }

    res.status(200).json({ 
      message: "Login successful!", 
      user: {
        email: userRow[0],
        nameOfUser: userRow[2],
        userType: userRow[3],
        department: userRow[4],
        nameOfEndUser: userRow[5],
        contactNumber: userRow[6]
      } 
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to connect to database." });
  }
});


// ====================================================================
// ADMINISTRATIVE ENDPOINTS: ACCOUNTS ACCESS AUDIT AND LIFECYCLE
// ====================================================================

app.get('/api/users', async (req, res) => {
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "Sheet1!A:I" 
    });

    const rows = response.data.values;
    if (!rows || rows.length <= 1) return res.status(200).json([]);

    const formattedUsers = rows.slice(1).map((row) => ({
      email: row[0] || '',
      nameOfUser: row[2] || '',
      userType: row[3] || 'Regular User',
      department: row[4] || '',
      nameOfEndUser: row[5] || '',
      contactNumber: row[6] || '',
      timestamp: row[7] || '',
      status: row[8] || 'Pending' 
    }));

    res.status(200).json(formattedUsers);
  } catch (error) {
    console.error("Error reading accounts directory table:", error);
    res.status(500).json({ message: "Failed to load system user directories." });
  }
});

app.post('/api/users/update', async (req, res) => {
  const { email, userType, department, status } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "Sheet1!A:I" });
    const rows = response.data.values;

    let targetRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] && rows[i][0].trim().toLowerCase() === email.trim().toLowerCase()) {
        targetRowIndex = i + 1; 
        break;
      }
    }

    if (targetRowIndex === -1) return res.status(404).json({ message: "User account identifier profile not found." });

    while (rows[targetRowIndex - 1].length < 9) {
      rows[targetRowIndex - 1].push('');
    }

    rows[targetRowIndex - 1][3] = userType;
    rows[targetRowIndex - 1][4] = department;
    rows[targetRowIndex - 1][8] = status || rows[targetRowIndex - 1][8] || 'Pending'; 

    await googleSheets.spreadsheets.values.update({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: `Sheet1!A${targetRowIndex}:I${targetRowIndex}`, 
      valueInputOption: "USER_ENTERED",
      resource: { values: [rows[targetRowIndex - 1]] }
    });

    res.status(200).json({ message: "User credentials and status flags saved successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to adjust user specifications." });
  }
});

app.post('/api/users/delete', async (req, res) => {
  const { email } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "Sheet1!A:I" });
    let rows = response.data.values;

    if (!rows) return res.status(404).json({ message: "Database user sheet is completely empty." });

    const initialLength = rows.length;
    rows = rows.filter(row => row[0] && row[0].trim().toLowerCase() !== email.trim().toLowerCase());

    if (rows.length === initialLength) return res.status(404).json({ message: "Target account registry key does not exist." });

    await googleSheets.spreadsheets.values.clear({ auth, spreadsheetId: SPREADSHEET_ID, range: "Sheet1!A2:I1000" });

    if (rows.length > 1) {
      await googleSheets.spreadsheets.values.update({
        auth, spreadsheetId: SPREADSHEET_ID, range: `Sheet1!A1:I${rows.length}`,
        valueInputOption: "USER_ENTERED", resource: { values: rows }
      });
    }

    res.status(200).json({ message: "Account cleanly wiped from system tracking matrix." });
  } catch (error) {
    res.status(500).json({ message: "Failed to execute database account truncation." });
  }
});


// ==========================================
// LDIP ROUTE MAP CONTROLLERS
// ==========================================
app.post('/api/ldip', async (req, res) => {
  const entryData = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const newLdipRow = [
      [
        entryData.office,
        entryData.sectorCode,
        entryData.sectorName,
        entryData.title,
        entryData.description,
        entryData.targets.join(', '), 
        entryData.budget,
        entryData.timestamp
      ]
    ];

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "LDIP!A:H", 
      valueInputOption: "USER_ENTERED",
      resource: { values: newLdipRow },
    });

    res.status(200).json({ message: "LDIP entry synchronized successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Failed to commit record entry." });
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

    const filteredEntries = rows.slice(1)
      .filter(row => {
        if (!row[0] || department.trim().toLowerCase() === 'all') return true;
        return row[0].toString().trim().toLowerCase() === department.trim().toLowerCase();
      })
      .map((row, index) => ({
        id: index,
        office: row[0] || 'Unknown',
        sectorCode: row[1] || '0000',
        sectorName: row[2] || 'Unassigned',
        title: row[3] || 'Untitled Program',
        description: row[4] || '',
        targets: row[5] ? row[5].split(', ') : [], 
        budget: cleanParseFloat(row[6]), 
        timestamp: row[7] || ''
      }));

    res.status(200).json(filteredEntries.reverse());
  } catch (error) {
    res.status(500).json({ message: "Failed to retrieve records from cloud ledger." });
  }
});


// ==========================================
// AIP ROUTE MAP CONTROLLERS
// ==========================================
app.post('/api/aip', async (req, res) => {
  const { entries } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const aipRows = entries.map(entry => [
      entry.aipRefCode,                       
      entry.office,                           
      entry.programTitle,                     
      entry.projectName,                      
      entry.activityName || 'N/A (Standalone Project)', 
      entry.implementingOffice,               
      entry.startDate,                        
      entry.completionDate,                   
      entry.expectedOutput,                   
      entry.fundingSource,                    
      entry.ps,                               
      entry.mooe,                             
      entry.co,                               
      entry.total,                            
      entry.ccAdaptation,                     
      entry.ccMitigation,                     
      entry.ccTypology,                       
      new Date().toLocaleString()             
    ]);

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "AIP!A:R", 
      valueInputOption: "USER_ENTERED",
      resource: { values: aipRows },
    });

    res.status(200).json({ message: "AIP entries synchronized successfully!" });
  } catch (error) {
    console.error("Error writing to AIP tab:", error);
    res.status(500).json({ message: "Failed to sync AIP dataset rows." });
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

    const filteredEntries = rows.slice(1)
      .filter(row => {
        if (!row[1] || department.trim().toLowerCase() === 'all') return true;
        return row[1].toString().trim().toLowerCase() === department.trim().toLowerCase();
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
    console.error("Error reading from AIP tab:", error);
    res.status(500).json({ message: "Failed to retrieve records from cloud ledger." });
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
      valueInputOption: "USER_ENTERED", resource: { values: updatedValues }
    });

    res.status(200).json({ message: "AIP entry updated successfully." });
  } catch (error) {
    console.error("AIP update endpoint crashed:", error);
    res.status(500).json({ message: "Failed to update AIP entry." });
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
      entry.aipRefCode,           
      entry.office,               
      entry.programTitle,         
      entry.projectName,          
      entry.activityName,         
      entry.implementingOffice,   
      entry.performanceIndicator, 
      entry.targetBudgetYear,     
      entry.ps,                   
      entry.mooe,                 
      entry.co,                   
      entry.total,                
      entry.includesProcurement || 'No', 
      new Date().toLocaleString()        
    ]];

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "BudgetForm4!A:M", 
      valueInputOption: "USER_ENTERED",
      resource: { values: newBudgetRow },
    });

    res.status(200).json({ message: "Annual budget row synchronized with Local Budget Form No. 4 ledger!" });
  } catch (error) {
    console.error("Error writing to BudgetForm4 tab:", error);
    res.status(500).json({ message: "Failed to execute database logging for Form 4." });
  }
});

app.get('/api/budget/:department', async (req, res) => {
  const { department } = req.params;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "BudgetForm4!A:M" });
    const rows = response.data.values;

    if (!rows || rows.length <= 1) return res.status(200).json([]);

    const filteredEntries = rows.slice(1)
      .filter(row => {
        if (!row[1] || department.trim().toLowerCase() === 'all') return true;
        return row[1].toString().trim().toLowerCase() === department.trim().toLowerCase();
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
    res.status(500).json({ message: "Failed to read data matrix from spreadsheet." });
  }
});


// ==========================================
// PPMP ROUTE MAP CONTROLLERS
// ==========================================
app.post('/api/ppmp', async (req, res) => {
  const { entries } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const ppmpRows = entries.map(entry => [
      entry.aipRefCode,              
      entry.office,                  
      entry.generalDescription,      
      entry.typeOfProject,           
      entry.preProcurementConference,
      entry.startProcurementMonth,   
      entry.endProcurementMonth,     
      entry.expectedDeliveryMonth,   
      entry.sourceOfFunds,           
      entry.estimatedBudget,         
      JSON.stringify(entry.items || []), 
      new Date().toLocaleString()    
    ]);

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "PPMP!A:L",
      valueInputOption: "USER_ENTERED",
      resource: { values: ppmpRows },
    });

    res.status(200).json({ message: "Procurement shells batch-synchronized safely." });
  } catch (error) {
    console.error("Error appending procurement logs:", error);
    res.status(500).json({ message: "Failed to execute bulk batch creation." });
  }
});

app.post('/api/ppmp/update', async (req, res) => {
  const { aipRefCode, updatedPlan } = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "PPMP!A:L" });
    const rows = response.data.values;

    let targetRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] === aipRefCode) {
        targetRowIndex = i + 1;
        break;
      }
    }

    if (targetRowIndex === -1) return res.status(404).json({ message: "Target procurement plan reference row not found." });

    const updatedRowValues = [[
      aipRefCode,
      updatedPlan.office,
      updatedPlan.generalDescription,
      updatedPlan.typeOfProject,
      updatedPlan.preProcurementConference,
      updatedPlan.startProcurementMonth,
      updatedPlan.endProcurementMonth,
      updatedPlan.expectedDeliveryMonth,
      updatedPlan.sourceOfFunds,
      updatedPlan.estimatedBudget,
      JSON.stringify(updatedPlan.items || []),
      new Date().toLocaleString()
    ]];

    await googleSheets.spreadsheets.values.update({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: `PPMP!A${targetRowIndex}:L${targetRowIndex}`,
      valueInputOption: "USER_ENTERED",
      resource: { values: updatedRowValues }
    });

    res.status(200).json({ message: "Procurement plan specifications updated cleanly." });
  } catch (error) {
    console.error("Update error inside PPMP log sheet:", error);
    res.status(500).json({ message: "Failed to rewrite spreadsheet row parameters." });
  }
});

app.get('/api/ppmp/:department', async (req, res) => {
  const { department } = req.params;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "PPMP!A:L" });
    const rows = response.data.values;

    if (!rows || rows.length <= 1) return res.status(200).json([]);

    const filteredEntries = rows.slice(1)
      .filter(row => {
        if (!row[1] || department.trim().toLowerCase() === 'all') return true;
        return row[1].toString().trim().toLowerCase() === department.trim().toLowerCase();
      })
      .map((row, index) => {
        let parsedItems = [];
        try { parsedItems = JSON.parse(row[10] || '[]'); } catch (e) { parsedItems = []; }

        return {
          id: index,
          aipRefCode: row[0] || '',
          office: row[1] || '',
          generalDescription: row[2] || '',
          typeOfProject: row[3] || 'Goods',
          preProcurementConference: row[4] || 'No',
          startProcurementMonth: row[5] || '',
          endProcurementMonth: row[6] || '',
          expectedDeliveryMonth: row[7] || '',
          sourceOfFunds: row[8] || '',
          estimatedBudget: cleanParseFloat(row[9]),
          items: parsedItems,
          timestamp: row[11] || ''
        };
      });

    res.status(200).json(filteredEntries.reverse());
  } catch (error) {
    console.error("Error processing procurement database extraction arrays:", error);
    res.status(500).json({ message: "Failed to map network data matrix stream fields." });
  }
});


// ==========================================
// NEW: ANNUAL PROCUREMENT PLAN (APP) ENDPOINTS
// ==========================================
app.post('/api/app', async (req, res) => {
  const entry = req.body;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const newAppRow = [[
      entry.aipRefCode,              
      entry.projectTitle,            
      entry.endUserUnit,             
      entry.modeOfProcurement,       
      entry.earlyProcurementActivity,
      entry.criteriaForBidEvaluation,
      entry.startProcurementMonth,   
      entry.endProcurementMonth,     
      entry.sourceOfFunds,           
      entry.approvedBudget,          
      entry.procurementStrategyTools,
      entry.remarks,                 
      new Date().toLocaleString()    
    ]];

    await googleSheets.spreadsheets.values.append({
      auth,
      spreadsheetId: SPREADSHEET_ID,
      range: "APP!A:M",
      valueInputOption: "USER_ENTERED",
      resource: { values: newAppRow },
    });

    res.status(200).json({ message: "APP row logged successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to log APP entry." });
  }
});

app.get('/api/app', async (req, res) => {
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });
    const response = await googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "APP!A:M" });
    const rows = response.data.values;
    if (!rows || rows.length <= 1) return res.status(200).json([]);

    const formattedApp = rows.slice(1).map((row, index) => ({
      id: index,
      aipRefCode: row[0] || '',
      projectTitle: row[1] || '',
      endUserUnit: row[2] || '',
      modeOfProcurement: row[3] || '',
      earlyProcurementActivity: row[4] || '',
      criteriaForBidEvaluation: row[5] || '',
      startProcurementMonth: row[6] || '',
      endProcurementMonth: row[7] || '',
      sourceOfFunds: row[8] || '',
      approvedBudget: cleanParseFloat(row[9]),
      procurementStrategyTools: row[10] || '',
      remarks: row[11] || '',
      timestamp: row[12] || ''
    }));

    res.status(200).json(formattedApp.reverse());
  } catch (error) {
    res.status(500).json({ message: "Failed to retrieve APP ledger." });
  }
});


// ==========================================
// MASTER GLOBAL AGGREGATION DASHBOARD ENDPOINT 
// ==========================================
app.get('/api/dashboard/stats/:department', async (req, res) => {
  const { department } = req.params;
  try {
    const client = await auth.getClient();
    const googleSheets = google.sheets({ version: "v4", auth: client });

    const [ldipRes, aipRes, budgetRes, ppmpRes] = await Promise.all([
      googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "LDIP!A:H" }),
      googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "AIP!A:R" }),
      googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "BudgetForm4!A:M" }),
      googleSheets.spreadsheets.values.get({ auth, spreadsheetId: SPREADSHEET_ID, range: "PPMP!A:L" })
    ]);

    const ldipRows = ldipRes.data.values || [];
    const aipRows = aipRes.data.values || [];
    const budgetRows = budgetRes.data.values || [];
    const ppmpRows = ppmpRes.data.values || [];

    const dClean = department.trim().toLowerCase();

    const filteredLdip = ldipRows.slice(1).filter(r => !r[0] || dClean === 'all' || r[0].toString().trim().toLowerCase() === dClean);
    const ldipCount = filteredLdip.length;
    const ldipTotal = filteredLdip.reduce((acc, curr) => acc + cleanParseFloat(curr[6]), 0);

    const filteredAip = aipRows.slice(1).filter(r => (!r[1] || dClean === 'all' || r[1].toString().trim().toLowerCase() === dClean) && r[4] !== 'PENDING_CONFIG');
    const aipCount = filteredAip.length;
    const aipTotal = filteredAip.reduce((acc, curr) => acc + cleanParseFloat(curr[13]), 0);

    const filteredBudget = budgetRows.slice(1).filter(r => !r[1] || dClean === 'all' || r[1].toString().trim().toLowerCase() === dClean);
    const budgetTotal = filteredBudget.reduce((acc, curr) => acc + cleanParseFloat(curr[11]), 0);
    const budgetPs = filteredBudget.reduce((acc, curr) => acc + cleanParseFloat(curr[8]), 0);
    const budgetMooe = filteredBudget.reduce((acc, curr) => acc + cleanParseFloat(curr[9]), 0);
    const budgetCo = filteredBudget.reduce((acc, curr) => acc + cleanParseFloat(curr[10]), 0);

    const filteredPpmp = ppmpRows.slice(1).filter(r => !r[1] || dClean === 'all' || r[1].toString().trim().toLowerCase() === dClean);
    const ppmpTotal = filteredPpmp.reduce((acc, curr) => acc + cleanParseFloat(curr[9]), 0);

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
  console.log('Server is listening on http://localhost:5000');
});