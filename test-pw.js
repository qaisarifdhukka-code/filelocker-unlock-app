import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  
  page.on('console', msg => console.log('PAGE LOG:', msg.type(), msg.text()));
  page.on('pageerror', error => console.log('PAGE ERROR:', error.message));
  
  await page.goto('http://localhost:4173/company-name/qeFlY1ZDe0RVoVJz', { waitUntil: 'networkidle' });
  
  console.log('Page loaded successfully');
  await browser.close();
})();
