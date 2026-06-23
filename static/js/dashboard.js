let riskChart;
let hourlyChart;
async function loadStats(){
    const response=await fetch('api/stats');
    const data=await response.json();
    document.getElementById('total').innerText=data.total;
    document.getElementById('ips').innerText=data.unique_ips;
    document.getElementById('high').innerText=data.high_risk;
}
async function loadTable(){
    const response=await fetch('/api/recent');
    const rows=await response.json();
    let html="";
    rows.forEach(row=>{
        html+=`
        <tr>
            <td>${row.timestamp}</td>
            <td>${row.src_ip}</td>
            <td>${row.service}</td>
            <td>${row.event_type}</td>
            <td>${row.aei_score}</td>
        </tr>
        `;
    });
    document.getElementById("attackTable").innerHTML=html;
}

async function loadAEIChart(){
    const response=await fetch('/api/aei');
    const data=await response.json();
    const ctx=document.getElementById('riskChart').getContext('2d');
    if(riskChart){
        riskChart.destroy();
    }
    riskChart=new Chart(ctx,{
        type:'pie',
        data:{
            labels:['low','Medium','High'],
            datasets:[{
                data:[
                    data.low,
                    data.medium,
                    data.high_risk],
                    backgroundColor:[
                        '#22c55e',
                        '#f59e0b',
                        '#ef4444'
                    ]
            }]
        }
    });
}

async function loadHourlyChart(){
    const response=await fetch('/api/hourly');
    const data=await response.json();
    const labels=data.map(item=>item.hour);
    const values=data.map(item=>item.attacks);
    const ctx=document.getElementById('hourlyChart').getContext('2d');
    if(hourlyChart){
        hourlyChart.destroy();
    }
    hourlyChart=new Chart(ctx,{
        type:'bar',
        data:{
            labels:labels,
            datasets:[{
                label:'Attacks',
                data:values
            }]
        }
    });
}

loadStats();
loadTable();
loadAEIChart();
loadHourlyChart();
setInterval(loadStats,5000);
setInterval(loadTable,5000);
setInterval(loadAEIChart,5000);
setInterval(loadHourlyChart,5000);