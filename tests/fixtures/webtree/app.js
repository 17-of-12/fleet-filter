function renderTable(rows){var out=[];for(var i=0;i<rows.length;i++){out.push("<tr><td>"+rows[i].name+"</td><td>"+rows[i].year+"</td></tr>");}
document.getElementById("results").innerHTML=out.join("");}
