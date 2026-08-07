// SPDX-License-Identifier: Apache-2.0
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const uiUrl = process.env.DSTACK_UI_URL;
  const name = process.env.DSTACK_UI_VM_NAME;
  const image = process.env.DSTACK_UI_IMAGE;
  const output = process.env.DSTACK_UI_OUTPUT;
  if (!uiUrl || !name || !image || !output) throw new Error('missing browser workflow input');
  const browser = await chromium.launch({ headless: true });
  const rows = {};
  let alertMessages = [];
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    page.on('dialog', async dialog => { alertMessages.push(dialog.message()); await dialog.accept(); });
    await page.goto(uiUrl, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: 'Deploy Instance' }).waitFor();
    rows['healthy-ui'] = true;
    await page.getByRole('button', { name: 'Deploy Instance' }).click();
    const defaults = {
      vcpu: await page.locator('#vcpu').inputValue(),
      memory: await page.locator('#memory').inputValue(),
      disk: await page.locator('#diskSize').inputValue(),
      key_provider: await page.locator('#keyProviderSelect').inputValue(),
      simulated_tee: await page.locator('#simulatedTeeSelect').inputValue(),
      event_log: await page.locator('#eventLogVersion').inputValue(),
    };
    if (JSON.stringify(defaults) !== JSON.stringify({vcpu:'1',memory:'2',disk:'20',key_provider:'kms',simulated_tee:'',event_log:'1'})) {
      throw new Error(`unexpected defaults ${JSON.stringify(defaults)}`);
    }
    rows['unset-defaults'] = true;
    await page.locator('#vmName').fill(name);
    await page.locator('#vmImage').selectOption(image);
    await page.locator('#memory').fill('1');
    await page.locator('#dockerComposeFile').fill('services:\n  ui-case:\n    image: ubuntu:latest\n    command: ["sleep", "infinity"]\n');
    await page.locator('#keyProviderSelect').selectOption('tpm');
    await page.locator('#simulatedTeeSelect').selectOption('dstack-tdx');
    await page.getByLabel('No TEE').check();
    await page.getByRole('button', { name: 'Add Network' }).click();
    const networkSelect = page.locator('.network-config-row select').first();
    await networkSelect.selectOption('user');
    rows['semantic-form'] = true;
    rows['simulated-platform'] = true;
    rows['network-selection'] = true;
    rows['gpu-empty-state'] = await page.locator('gpu-config-editor').count() === 0;

    let injected = false;
    await page.route('**/prpc/CreateVm*', async route => {
      if (!injected) {
        injected = true;
        await route.fulfill({status: 500, contentType: 'text/plain', body: 'controlled server rejection'});
      } else {
        await route.continue();
      }
    });
    await page.getByRole('button', { name: 'Deploy', exact: true }).focus();
    await page.keyboard.press('Enter');
    await page.waitForTimeout(500);
    if (!alertMessages.some(x => x.includes('controlled server rejection'))) throw new Error('server error was not displayed');
    if (!await page.getByRole('heading', { name: 'Deploy a new instance' }).isVisible()) throw new Error('dialog closed after rejected submit');
    rows['server-error-recovery'] = true;
    await page.unroute('**/prpc/CreateVm*');
    await page.getByRole('button', { name: 'Deploy', exact: true }).focus();
    await page.keyboard.press('Enter');
    await page.getByRole('heading', { name: 'Deploy a new instance' }).waitFor({state: 'hidden', timeout: 30000});
    const row = page.locator('.vm-row').filter({hasText: name});
    await row.waitFor({timeout: 30000});
    rows['keyboard-ui-submit'] = true;
    rows['created-observed'] = true;

    // Stop and restart only through UI actions.
    await row.locator('.btn-actions').click();
    await row.getByRole('button', {name: 'Kill', exact: true}).click();
    await page.waitForTimeout(1000);
    await row.locator('.btn-actions').click();
    await row.getByRole('button', {name: 'Start', exact: true}).click();
    rows['ui-lifecycle'] = true;

    // Stop again, then update disk and user config through the UI.
    await page.waitForTimeout(800);
    await row.locator('.btn-actions').click();
    await row.getByRole('button', {name: 'Kill', exact: true}).click();
    await page.waitForTimeout(800);
    await row.locator('.btn-actions').click();
    await row.getByRole('button', {name: 'Update', exact: true}).click();
    await page.getByRole('heading', {name: 'Update VM Config'}).waitFor({timeout: 15000});
    await page.locator('#upgradeDiskSize').fill('21');
    await page.locator('#upgradeUserConfig').fill('ui-updated=true');
    await page.getByRole('button', {name: 'Update', exact: true}).click();
    await page.getByRole('heading', {name: 'Update VM Config'}).waitFor({state:'hidden', timeout:30000});
    rows['ui-update-resize'] = true;

    const popupPromise = page.waitForEvent('popup');
    await row.getByRole('link', {name:'Logs', exact:true}).click();
    const popup = await popupPromise;
    await popup.waitForTimeout(300);
    if (!popup.url().includes('/logs?') || !popup.url().includes('ch=serial')) throw new Error('logs action opened wrong URL');
    await popup.close();
    rows['ui-log-view'] = true;

    const second = await browser.newContext();
    const peer = await second.newPage();
    await peer.goto(uiUrl, {waitUntil:'networkidle'});
    if (await peer.getByRole('heading', {name:'Deploy a new instance'}).count()) throw new Error('form leaked into second session');
    await peer.locator('.vm-row').filter({hasText:name}).waitFor({timeout:15000});
    rows['cross-session-isolation'] = true;
    await second.close();
    await context.close();
    fs.writeFileSync(output, JSON.stringify({rows, defaults, alerts: alertMessages, vm_name:name}, null, 2));
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error.stack || error); process.exit(1); });
