// Define recommendations mapping (similar to old implementation)
const RECOMMENDATIONS_MAP = {
    "CC1.5": "Your latest commit is unsigned. To fix this: 1. gpg --full-generate-key 2. git config --global commit.gpgsign true 3. git commit --amend --no-edit -S",
    // Add more mappings as needed
    // Example: "CC6.1": "Ensure all API endpoints require authentication..."
};

function renderReport(data) {
    if (!data) {
        console.error("No data provided to renderReport.");
        return;
    }

    // Populate Summary Stats
    document.getElementById('framework-value').textContent = data.metadata.framework || 'Loading...';
    document.getElementById('pass-count').textContent = data.stats.pass || '0';
    document.getElementById('fail-count').textContent = data.stats.fail || '0';
    document.getElementById('total-count').textContent = data.stats.pass + data.stats.fail || '0';

    // Calculate overall status
    const overallStatus = data.stats.fail > 0 ? 'FAIL' : 'PASS';
    document.getElementById('status-value').innerHTML = `<span class="status-${overallStatus.toLowerCase()}">${overallStatus}</span>` || 'Processing...';

    document.getElementById('files-count').textContent = data.metadata.files_scanned || '0';
    document.getElementById('path-value').textContent = data.metadata.target_path || 'Unknown';
    document.getElementById('integrity-hash').textContent = data.metadata.integrity_hash || 'N/A';

    // Populate Findings Table
    const tbody = document.getElementById('findings-tbody');
    data.findings.forEach(finding => {
        const row = document.createElement('tr');

        const statusClass = finding.status === 'PASS' ? 'status-pass' : 'status-fail';
        const statusText = finding.status;

        row.innerHTML = `
            <td>${finding.id}</td>
            <td>${finding.type}</td>
            <td>${finding.control}</td>
            <td><span class="${statusClass}">${statusText}</span></td>
            <td>
                ${finding.status === 'FAIL' ?
                    `<button class="toggle-details" onclick="toggleEvidence(this)">Show Evidence</button>
                     <div class="evidence-details" id="details-${finding.id}">
                        <pre>${JSON.stringify(finding.evidence, null, 2)}</pre>
                     </div>`
                    :
                    '<span>N/A</span>'
                }
            </td>
        `;
        tbody.appendChild(row);
    });

    // Draw Simple Chart
    drawSimpleChart(data.stats.pass, data.stats.fail);

    // --- Dynamic Recommendations Section ---
    const recommendationsSectionPlaceholder = document.getElementById('recommendations-section-placeholder');
    const recommendationsList = document.getElementById('recommendations-list');

    // Find failed findings
    const failedFindings = data.findings.filter(finding => finding.status === 'FAIL');

    if (failedFindings.length > 0) {
        // Clear any existing recommendations
        recommendationsList.innerHTML = '';

        // Generate recommendations based on failed findings
        failedFindings.forEach(finding => {
            const controlId = finding.id; // Use the finding's ID
            const recommendationText = RECOMMENDATIONS_MAP[controlId];

            if (recommendationText) {
                const listItemHtml = `
                    <li><strong>${controlId}:</strong> ${recommendationText}</li>
                `;
                recommendationsList.insertAdjacentHTML('beforeend', listItemHtml);
            } else {
                // Fallback if no specific recommendation is mapped
                const fallbackText = `No specific recommendation found for control ${controlId}. Please review the control objective and evidence.`;
                const listItemHtml = `
                    <li><strong>${controlId}:</strong> ${fallbackText}</li>
                `;
                recommendationsList.insertAdjacentHTML('beforeend', listItemHtml);
            }
        });

        // Show the recommendations section
        recommendationsSectionPlaceholder.style.display = 'block';
    } else {
        // Hide the recommendations section if no failures
        recommendationsSectionPlaceholder.style.display = 'none';
    }
    // --- End Dynamic Recommendations ---
}

function toggleEvidence(button) {
    const detailsId = button.nextElementSibling.id;
    const detailsDiv = document.getElementById(detailsId);
    if (detailsDiv.style.display === 'none' || detailsDiv.style.display === '') {
        detailsDiv.style.display = 'block';
        button.textContent = 'Hide Evidence';
    } else {
        detailsDiv.style.display = 'none';
        button.textContent = 'Show Evidence';
    }
}

function drawSimpleChart(passCount, failCount) {
    const canvas = document.getElementById('resultsChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const total = passCount + failCount;

    if (total === 0) return;

    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 10;

    let startAngle = 0;
    const passFraction = passCount / total;
    const failFraction = failCount / total;

    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.arc(centerX, centerY, radius, startAngle, startAngle + (Math.PI * 2 * passFraction));
    ctx.closePath();
    ctx.fillStyle = '#073b0f';
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.arc(centerX, centerY, radius, startAngle + (Math.PI * 2 * passFraction), startAngle + (Math.PI * 2 * (passFraction + failFraction)));
    ctx.closePath();
    ctx.fillStyle = '#8c1515';
    ctx.fill();
}

window.renderReport = renderReport;
window.toggleEvidence = toggleEvidence;
window.drawSimpleChart = drawSimpleChart;