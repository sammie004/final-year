const { Builder, By, Key, until } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');

(async function runTests() {
  let options = new chrome.Options();
  // Uncomment for headless mode if desired:
  // options = options.headless();

  let driver = await new Builder().forBrowser('chrome').setChromeOptions(options).build();

  try {
    // ******************************************
    // TC-001: User Sign-Up Test (Unique Credentials)
    // ******************************************
    await driver.get('http://localhost:3000/sign-up');
    
    await driver.wait(until.elementLocated(By.name('username')), 10000);
    await driver.findElement(By.name('username')).sendKeys('testuser12');
    
    await driver.wait(until.elementLocated(By.name('email')), 5000);
    await driver.findElement(By.name('email')).sendKeys('testuser12@example.com');
    
    await driver.wait(until.elementLocated(By.name('password')), 5000);
    await driver.findElement(By.name('password')).sendKeys('Test123!');
    
    await driver.wait(until.elementLocated(By.name('role')), 5000);
    await driver.findElement(By.name('role')).sendKeys('student');
    
    await driver.wait(until.elementLocated(By.name('department')), 5000);
    await driver.findElement(By.name('department')).sendKeys('Computer Science');
    
    await driver.wait(until.elementLocated(By.id('signupBtn')), 5000);
    await driver.findElement(By.id('signupBtn')).click();
    
    // Handle the alert (if present)
    try {
      await driver.wait(until.alertIsPresent(), 5000);
      let alert = await driver.switchTo().alert();
      let alertText = await alert.getText();
      console.log('TC-001: Sign Up Alert Text:', alertText);
      await alert.accept();
    } catch (alertErr) {
      console.log('TC-001: No alert present after sign-up:', alertErr.message);
    }
    
    console.log('TC-001 Passed: Sign-up completed with unique credentials.');

    // ******************************************
    // TC-004: User Login Test (Student Login)
    // ******************************************
    await driver.get('http://localhost:3000/login');

    await driver.wait(until.elementLocated(By.id('email')), 10000);
    await driver.findElement(By.id('email')).sendKeys('testuser12@example.com');

    await driver.wait(until.elementLocated(By.id('password')), 5000);
    await driver.findElement(By.id('password')).sendKeys('Test123!', Key.RETURN);

    // Wait for the student dashboard to load
    await driver.wait(until.urlContains('/student'), 15000);
    console.log('TC-004 Passed: Redirected to student dashboard.');

    // ******************************************
    // Navigate to Request Submission Page from Dashboard
    // ******************************************
    // Wait for the button that navigates to the request submission page
    await driver.wait(until.elementLocated(By.id('requestBtn')), 10000);
    let requestBtn = await driver.findElement(By.id('requestBtn'));

    // Use JavaScript click as a fallback
    await driver.executeScript("arguments[0].click();", requestBtn);
    await driver.sleep(3000); // Wait for page transition
    let currentUrl = await driver.getCurrentUrl();
    console.log("Current URL after clicking request button:", currentUrl);
    if (!currentUrl.includes('/request-request')) {
      throw new Error("Navigation to request page failed.");
    }
    console.log('Navigated to Request Submission Page.');

    // ******************************************
    // TC-013: Request Submission Test (with Lecturer Selection)
    // ******************************************
    await driver.wait(until.elementLocated(By.name('course_code')), 10000);
    await driver.findElement(By.name('course_code')).sendKeys('CS101');

    await driver.wait(until.elementLocated(By.name('course_title')), 5000);
    await driver.findElement(By.name('course_title')).sendKeys('Intro to Computer Science');

    await driver.wait(until.elementLocated(By.name('level_taken')), 5000);
    await driver.findElement(By.name('level_taken')).sendKeys('100');

    await driver.wait(until.elementLocated(By.name('issues')), 5000);
    await driver.findElement(By.name('issues')).sendKeys('Requesting urgent upload');

    // Lecturer Selection (assumed field name is 'lecturer_id')
    await driver.wait(until.elementLocated(By.name('lecturer_id')), 5000);
    await driver.findElement(By.name('lecturer_id')).sendKeys('asimonye');

    await driver.wait(until.elementLocated(By.id('submitRequestBtn')), 5000);
    await driver.findElement(By.id('submitRequestBtn')).click();

    await driver.wait(until.elementLocated(By.id('requestSuccessMsg')), 10000);
    let reqMsg = await driver.findElement(By.id('requestSuccessMsg')).getText();
    console.log('TC-013 Passed: Request Submission Success Message:', reqMsg);

    // ******************************************
    // TC-015: SQL Injection Attempt Test
    // ******************************************
    await driver.get('http://localhost:3000/request-upload');
    
    await driver.wait(until.elementLocated(By.name('course_code')), 10000);
    await driver.findElement(By.name('course_code')).sendKeys("CS101'; DROP TABLE users;--");

    await driver.wait(until.elementLocated(By.name('course_title')), 5000);
    await driver.findElement(By.name('course_title')).sendKeys('Injection Test');

    await driver.wait(until.elementLocated(By.name('level_taken')), 5000);
    await driver.findElement(By.name('level_taken')).sendKeys('100');

    await driver.wait(until.elementLocated(By.name('issues')), 5000);
    await driver.findElement(By.name('issues')).sendKeys('Test SQL Injection');

    // Lecturer selection for injection test, if required
    await driver.wait(until.elementLocated(By.name('lecturer_id')), 5000);
    await driver.findElement(By.name('lecturer_id')).sendKeys('asimonye');

    await driver.wait(until.elementLocated(By.id('submitRequestBtn')), 5000);
    await driver.findElement(By.id('submitRequestBtn')).click();

    try {
      await driver.wait(until.elementLocated(By.id('requestSuccessMsg')), 10000);
      let injectionMsg = await driver.findElement(By.id('requestSuccessMsg')).getText();
      console.log('TC-015 Warning: SQL Injection Test Message:', injectionMsg);
    } catch (e) {
      console.log('TC-015 Passed: SQL Injection test handled properly (no success message).');
    }

  } catch (err) {
    console.error('Test error:', err);
  } finally {
    await driver.quit();
  }
})();
