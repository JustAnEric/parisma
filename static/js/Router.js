/**
 * Function to handle settings page.
 */
const settings_page = async function() {
    const generalForm = document.querySelector('form .general-save-changes').parentElement;
    const wifiForm = document.querySelector('form .wifi-save-changes').parentElement;
    const advancedForm = document.querySelector('form .advanced-save-changes').parentElement;

    generalForm.addEventListener('submit', async (e) => {
        e.preventDefault()
        // Save general settings.
        const changes = [
            { name: "Router Name", type: "ROUTER_NAME", value: generalForm.querySelector('input[type="text"][name="ROUTER_NAME"]').value },
            { name: "Admin Password", type: "ADMIN_PASSWORD", value: generalForm.querySelector('input[type="password"][name="ADMIN_PASSWORD"]').value }
        ];
        const payload = {
            method: "POST",
            headers: { 'SETTINGS': JSON.stringify(changes) }
        };
        const request = (await fetch(`/router/api/save_settings/settings/1`, payload));
        const response = await request.json();
        console.log(response);
        if (!response.status) {
            alert("Failed to save changes.");
        } else {
            alert("Changes saved successfully.");
        }
        return false;
    });

    wifiForm.addEventListener('submit', async (e) => {
        e.preventDefault()
        // Save wifi settings.
        const changes = [
            { name: "SSID", type: "SSID", value: wifiForm.querySelector('input[type="text"][name="SSID"]').value },
            { name: "Security", type: "SECURITY", value: wifiForm.querySelector('select[name="SECURITY"]').value },
            { name: "Password", type: "PASSWORD", value: wifiForm.querySelector('input[type="password"][name="PASSWORD"]').value }
        ];
        const payload = {
            method: "POST",
            headers: { 'SETTINGS': JSON.stringify(changes) }
        };
        const request = (await fetch(`/router/api/save_settings/settings/2`, payload));
        const response = await request.json();
        console.log(response);
        if (!response.status) {
            alert("Failed to save changes.");
        } else {
            alert("Changes saved successfully.");
        }
        return false;
    });

    advancedForm.addEventListener('submit', async (e) => {
        e.preventDefault()
        // Save advanced settings.
        const changes = [
            { name: "LAN IP Address", type: "LAN_IP_ADDRESS", value: advancedForm.querySelector('input[type="text"][name="LAN_IP_ADDRESS"]').value },
            { name: "DHCP Range 1", type: "DHCP_RANGE_1", value: advancedForm.querySelector('input[type="text"][name="DHCP_RANGE_1"]').value },
            { name: "DHCP Range 2", type: "DHCP_RANGE_2", value: advancedForm.querySelector('input[type="text"][name="DHCP_RANGE_2"]').value }
        ];
        const payload = {
            method: "POST",
            headers: { 'SETTINGS': JSON.stringify(changes) }
        };
        const request = (await fetch(`/router/api/save_settings/settings/3`, payload));
        const response = await request.json();
        console.log(response);
        if (!response.status) {
            alert("Failed to save changes.");
        } else {
            alert("Changes saved successfully.");
        }
        return false;
    });
};


/**
 * Function to handle content blocking page.
 */
const contentBlocking_page = async function() {
    const editorTable = document.querySelector('div.flex table');
    const viewTable = document.querySelector('div.overflow-x-auto table');

    for (const d of viewTable.querySelector('tbody').children) {
        d.querySelector('button.delete-button').addEventListener('click', async (e) => {
            var payload = {
                method: 'GET',
                headers: {
                    'buffer-id': d.dataset.id
                }
            };
            console.log(payload);
            const request = await fetch(`/router/api/buffers/content_blocks/remove`, payload);
            const response = await request.json();
            console.log(response);
            if (!response.status) {
                alert('Failed to remove rule.');
            } else {
                d.remove();

                document.body.querySelector('main').insertAdjacentHTML('beforeend', `
                    <div id="toast-danger" class="flex items-center w-full max-w-xs p-4 mb-4 text-gray-500 bg-white rounded-lg shadow dark:text-gray-400 dark:bg-gray-800" role="alert">
                        <div class="inline-flex items-center justify-center flex-shrink-0 w-8 h-8 text-red-500 bg-red-100 rounded-lg dark:bg-red-800 dark:text-red-200">
                            <svg class="w-5 h-5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                                <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 11.793a1 1 0 1 1-1.414 1.414L10 11.414l-2.293 2.293a1 1 0 0 1-1.414-1.414L8.586 10 6.293 7.707a1 1 0 0 1 1.414-1.414L10 8.586l2.293-2.293a1 1 0 0 1 1.414 1.414L11.414 10l2.293 2.293Z"/>
                            </svg>
                            <span class="sr-only">Error icon</span>
                        </div>
                        <div class="ms-3 text-sm font-normal">Item has been deleted.</div>
                        <button type="button" class="ms-auto -mx-1.5 -my-1.5 bg-white text-gray-400 hover:text-gray-900 rounded-lg focus:ring-2 focus:ring-gray-300 p-1.5 hover:bg-gray-100 inline-flex items-center justify-center h-8 w-8 dark:text-gray-500 dark:hover:text-white dark:bg-gray-800 dark:hover:bg-gray-700 close-button" data-dismiss-target="#toast-danger" aria-label="Close">
                            <span class="sr-only">Close</span>
                            <svg class="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                                <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                            </svg>
                        </button>
                    </div>
                `);
                document.body.querySelector('#toast-danger').querySelector('#toast-danger .close-button').addEventListener('click', async()=>{
                    document.body.querySelector('#toast-danger').remove();
                });
                setTimeout(function () { try { document.body.querySelector('#toast-danger').remove() } catch {} }, 5000);
            }
        });
    }

    /*
    const payload = {
        method: 'GET',
        headers: {
            buffer: JSON.stringify({
                query: 'google.com.',
                macs: ['00:00:00:00:00'],
                status: true
            })
        }
    };
    */

    editorTable.querySelector('tbody tr.form button.add-new-rule').addEventListener('click', async (e) => {
        const macs = editorTable.querySelector('tbody tr.form input#mac-addresses[type="text"]').value;
        const query = editorTable.querySelector('tbody tr.form input#domain-rule[type="text"]').value;

        var mac_addresses = macs.length >= 3 ? (macs.includes(',') ? macs.split(',') : [macs]) : ["all"];
        var regex = /^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$/;
        var mac_regex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;

        if (!regex.test(query.trim())) {
            return alert('Invalid query string, supposed to be of type domain.');
        }

        // Clean up the MAC address input (trim, remove extra spaces, and ensure it's a valid array)
        let position = 0;
        for (let mac of mac_addresses) {
            mac = mac.trim();  // Remove any leading or trailing spaces

            if (mac !== "all") {  // Skip validation if it's "all"
                if (!mac_regex.test(mac)) {
                    alert(`Invalid mac address, pos ${position}, ${mac} is not valid.`);
                    return;
                }
            }

            position++;
        }

        var payload = {
            method: 'GET',
            headers: {
                buffer: JSON.stringify({
                    query: `${query.trim()}${(query.endsWith('.')) ? '' : '.'}`,
                    macs: mac_addresses,
                    status: true
                })
            }
        };

        const request = await fetch(`/router/api/buffers/content_blocks/add`, payload);
        const response = await request.json();
        console.log(response);
        if (!response.status) {
            alert('Failed to add new rule.');
        } else {
            viewTable.querySelector('tbody').insertAdjacentHTML('beforeend', `
                <tr data-id="${response.id}">
                    <td class="border border-gray-300 p-2">${query.trim()}${(query.endsWith('.')) ? '' : '.'}</td>
                    <td class="border border-gray-300 p-2">${mac_addresses.join(', ')}</td>
                    <td class="border border-gray-300 p-2">Active</td>
                    <td class="border border-gray-300 p-2"><button type="button" class="text-red delete-button" title="Delete">Delete</button></td>
                </tr>
            `);
            document.body.querySelector('main').insertAdjacentHTML('beforeend', `
<div id="toast-success" class="flex items-center w-full max-w-xs p-4 mb-4 text-gray-500 bg-white rounded-lg shadow dark:text-gray-400 dark:bg-gray-800" role="alert">
    <div class="inline-flex items-center justify-center flex-shrink-0 w-8 h-8 text-green-500 bg-green-100 rounded-lg dark:bg-green-800 dark:text-green-200">
        <svg class="w-5 h-5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
            <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 8.207-4 4a1 1 0 0 1-1.414 0l-2-2a1 1 0 0 1 1.414-1.414L9 10.586l3.293-3.293a1 1 0 0 1 1.414 1.414Z"/>
        </svg>
        <span class="sr-only">Check icon</span>
    </div>
    <div class="ms-3 text-sm font-normal">Item created successfully.</div>
    <button type="button" class="ms-auto -mx-1.5 -my-1.5 bg-white text-gray-400 hover:text-gray-900 rounded-lg focus:ring-2 focus:ring-gray-300 p-1.5 hover:bg-gray-100 inline-flex items-center justify-center h-8 w-8 dark:text-gray-500 dark:hover:text-white dark:bg-gray-800 dark:hover:bg-gray-700 close-button" data-dismiss-target="#toast-success" aria-label="Close">
        <span class="sr-only">Close</span>
        <svg class="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
            <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
        </svg>
    </button>
</div>
            `);
            document.body.querySelector('#toast-success').querySelector('#toast-success .close-button').addEventListener('click', async()=>{
                document.body.querySelector('#toast-success').remove();
            });
            setTimeout(function () { try { document.body.querySelector('#toast-success').remove() } catch {} }, 5000);
            const d = viewTable.querySelector('tbody').children[viewTable.querySelector('tbody').children.length - 1];
            d.querySelector('button.delete-button').addEventListener('click', async (e) => {
                var payload = {
                    method: 'GET',
                    headers: {
                        'buffer-id': d.dataset.id
                    }
                };
                const request = await fetch(`/router/api/buffers/content_blocks/remove`, payload);
                const response = await request.json();
                console.log(response);
                if (!response.status) {
                    alert('Failed to remove rule.');
                } else {
                    d.remove();
                }
                document.body.querySelector('main').insertAdjacentHTML('beforeend', `
<div id="toast-danger" class="flex items-center w-full max-w-xs p-4 mb-4 text-gray-500 bg-white rounded-lg shadow dark:text-gray-400 dark:bg-gray-800" role="alert">
    <div class="inline-flex items-center justify-center flex-shrink-0 w-8 h-8 text-red-500 bg-red-100 rounded-lg dark:bg-red-800 dark:text-red-200">
        <svg class="w-5 h-5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
            <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 11.793a1 1 0 1 1-1.414 1.414L10 11.414l-2.293 2.293a1 1 0 0 1-1.414-1.414L8.586 10 6.293 7.707a1 1 0 0 1 1.414-1.414L10 8.586l2.293-2.293a1 1 0 0 1 1.414 1.414L11.414 10l2.293 2.293Z"/>
        </svg>
        <span class="sr-only">Error icon</span>
    </div>
    <div class="ms-3 text-sm font-normal">Item has been deleted.</div>
    <button type="button" class="ms-auto -mx-1.5 -my-1.5 bg-white text-gray-400 hover:text-gray-900 rounded-lg focus:ring-2 focus:ring-gray-300 p-1.5 hover:bg-gray-100 inline-flex items-center justify-center h-8 w-8 dark:text-gray-500 dark:hover:text-white dark:bg-gray-800 dark:hover:bg-gray-700 close-button" data-dismiss-target="#toast-danger" aria-label="Close">
        <span class="sr-only">Close</span>
        <svg class="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
            <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
        </svg>
    </button>
</div>
                `);
                document.body.querySelector('#toast-danger').querySelector('#toast-danger .close-button').addEventListener('click', async()=>{
                    document.body.querySelector('#toast-danger').remove();
                });
                setTimeout(function () { try { document.body.querySelector('#toast-danger').remove() } catch {} }, 5000);
            });
        }
    });
};

/**
 * Function to handle captive portal page.
 */
const captivePortal_page = async function() {
    const toggleCaptivePortalCheckbox = document.querySelector('input#toggle-captive-portal[type="checkbox"]');
    const manageUsersTable = document.querySelector('main section table');

    toggleCaptivePortalCheckbox.addEventListener('change', async (e) => {
        const blockedTableDataRow = document.querySelector('td#blocked-table-data-row[colspan="5"]');
        if (e.target.checked) {
            if (blockedTableDataRow) {
                blockedTableDataRow.remove();
            } else {
                console.warn("Error, unknown blocked table data row");
            }

            if (manageUsersTable.querySelector('tbody').children.length > 0) {
                manageUsersTable.querySelector('tbody').innerHTML = '';
                console.warn("Users were already in table during creation");
            }

            // Add captive portal users to the table
            const captivePortalUsers = await fetch('/router/api/captive-portal/users', { headers: { 'passwords-needed': true } });
            const captivePortalUserData = await captivePortalUsers.json();

            captivePortalUserData.forEach(user => {
                manageUsersTable.querySelector('tbody').insertAdjacentHTML('beforeend', `
<tr data-id="${user.ID}">
    <td class="border border-gray-300 p-2 text-left">${user['name']}</td>
    <td class="border border-gray-300 p-2 text-left">${user['mac_assigned']} | Previously: ${user['mac_history']}</td>
    <td class="border border-gray-300 p-2 text-left">${user['status']}</td>
    <td class="border border-gray-300 p-2 text-left">${user['password']}</td>
    <td class="border border-gray-300 p-2 text-left"><button type="button" class="text-red-800 delete-button">Delete</button><br><button type="button" class="change-pw-button">Change Password</button><br><button type="button" class="del-mac-button">Delete MAC</button><br><button type="button" class="disable-button">Disable</button></td>
</tr>
                `);
                const userTableItem = manageUsersTable.querySelector('tbody').querySelector('tr[data-id="' + user.ID + '"]');

                userTableItem.querySelector('button.delete-button').addEventListener('click', async (e) => {
                    
                });

                userTableItem.querySelector('button.change-pw-button').addEventListener('click', async (e) => {
                    
                });

                userTableItem.querySelector('button.del-mac-button').addEventListener('click', async (e) => {
                    
                });

                userTableItem.querySelector('button.disable-button').addEventListener('click', async (e) => {
                    
                });
            });
        } else {
            manageUsersTable.querySelector('tbody').innerHTML = '<td class="border border-gray-300 p-2 text-left" id="blocked-table-data-row" colspan="5">Captive portal is disabled. We cannot show you this information.</td>';
        }
    });
};

if (window.location.pathname.includes('/network')) {
    VANTA.NET({
        el: "main header",
        mouseControls: true,
        touchControls: true,
        gyroControls: true,
        minHeight: 200.00,
        minWidth: 200.00,
        scale: 1.00,
        scaleMobile: 1.00,
        points: 20.000,
        color: 0xff41,
        backgroundColor: 0x0,
    });
} else if (window.location.pathname.includes('/statistics')) {
    VANTA.DOTS({
        el: "main header",
        mouseControls: true,
        touchControls: true,
        gyroControls: false,
        minHeight: 200.00,
        minWidth: 200.00,
        scale: 1.00,
        scaleMobile: 1.00
    });
} else if (window.location.pathname.includes('/home')) {
    VANTA.RINGS({
        el: "main header",
        mouseControls: true,
        touchControls: true,
        gyroControls: false,
        minHeight: 200.00,
        minWidth: 200.00,
        scale: 1.00,
        scaleMobile: 1.00
    });
} else if (window.location.pathname.includes('/devices')) {
    VANTA.GLOBE({
        el: "main header",
        mouseControls: true,
        touchControls: true,
        gyroControls: false,
        minHeight: 200.00,
        minWidth: 200.00,
        scale: 1.00,
        scaleMobile: 1.00,
        color: 0xff0057
    });
} else if (window.location.pathname.includes('/content-blocking')) {
    VANTA.GLOBE({
        el: "main header",
        mouseControls: true,
        touchControls: true,
        gyroControls: false,
        minHeight: 200.00,
        minWidth: 200.00,
        scale: 1.00,
        scaleMobile: 1.00,
        color: 0xff0057
    });

    contentBlocking_page();
} else if (window.location.pathname.includes('/settings')) {
    VANTA.CELLS({
        el: "main header",
        mouseControls: true,
        touchControls: true,
        gyroControls: false,
        minHeight: 200.00,
        minWidth: 200.00,
        scale: 1.00
    });

    settings_page();
} else if (window.location.pathname.includes('/captive-portal')) {
    VANTA.RINGS({
        el: "main header",
        mouseControls: true,
        touchControls: true,
        gyroControls: false,
        minHeight: 200.00,
        minWidth: 200.00,
        scale: 1.00,
        scaleMobile: 1.00
    });

    captivePortal_page();
}

/**
 * Reloads the current page.
 */
location.refresh = function() {
    return window.location.reload();
};