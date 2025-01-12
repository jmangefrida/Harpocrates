var addsecret = `
<h3>Add new secret</h3>
<p>
<form method=post>
  <input name='action' type='hidden' value='new_secret'>
  <input name='name' type='text' placeholder='Name'>
  <p><p>
  <input name='accountname' type='text' placeholder='AccountName'>
  <p>
  <input name='secret' type='password' placeholder='Secret'>
  <p>
  <input name='description' type='text' placeholder='Description'>
  <p>
  <input type='submit' name='submit' value='Save'>
</form>
`;

var addrole = `
<h3>Add new Role</h3>
<p>
<form method=post>
  <input name='action' type='hidden' value='new_role'>
  <input name='name' type='text' placeholder='Name'>
  <p><p>
  <input name='description' type='text' placeholder='Description'>
  <p>
  <input type='submit' name='submit' value='Save'>
</form>
`;

var addimage = `
<h3>Add new Image</h3>
<p>
<form method=post>
  <input name='action' type='hidden' value='new_image'>
  <input name='name' type='text' placeholder='Name'>
  <p><p>
  <select name='role' placeholder='Role'>
    <option>Role</option>`
    + roles + 
`
  </select>
  <p>
  <input name='description' type='text' placeholder='Description'>
  <p>
  <input type='submit' name='submit' value='Save'>
</form>
`;

var addadmin = `
<h3>Add new Admin</h3>
<p>
<form method=post>
  <input name='action' type='hidden' value='new_admin'>
  <input name='name' type='text' placeholder='UserName'>
  <p><p>
  <input name='password' type='password' placeholder='Password'>
  <p>
  <input type='submit' name='submit' value='Save'>
</form>
`;



var modal = document.getElementById("myModal");

// Get the button that opens the modal
var secret_btn = document.getElementById("new-secret");
var role_btn = document.getElementById("new-role");
var image_btn = document.getElementById("new-image");
var admin_btn = document.getElementById("new-admin");

// Get the <span> element that closes the modal
var span = document.getElementsByClassName("modal-close")[0];

var modalbody = document.getElementsByClassName("modal-inner-content")[0];

// When the user clicks the button, open the modal 
secret_btn.onclick = function() {
  modal.style.display = "block";
  modalbody.innerHTML = addsecret;
}

role_btn.onclick = function() {
  modal.style.display = "block";
  modalbody.innerHTML = addrole;
}

image_btn.onclick = function() {
  modal.style.display = "block";
  modalbody.innerHTML = addimage;
}

admin_btn.onclick = function() {
  modal.style.display = "block";
  modalbody.innerHTML = addadmin;
}

function manage_grant(role) {

  var managegrant = `
    <h3>Add Grant - ${role} </h3>
    <p>
    <form method=post>
      <input name='action' type='hidden' value='add_grant'>
      <input name='role' type='hidden' value='${role}'>
      <select id='select_grant' name='name' placeholder='Name'>
      </select>
      <p><p>
      <p>
      <input type='submit' name='submit' value='Add'>
    </form>
    <table id='tbl_grants'>
    </table>
    `;

  modalbody.innerHTML = managegrant;

  fetch('/secrets')
  .then(response => response.json())
  .then(data => {
    console.log(data);
    data.forEach(function(item, index) {
      var select = document.getElementById("select_grant");
      var option = document.createElement("option")
      option.value = item[0];
      option.innerHTML = item[0];
      select.add(option);
    });
  })
  .catch(error => {
    console.error("Error: ", error);
  });

  fetch('/grants/' + role)
  .then(response => response.json())
  .then(data => {
    console.log(data);
    data.forEach(function(item, index) {
      var table = document.getElementById("tbl_grants");
      var row = table.insertRow(-1);
      row.insertCell(0).innerHTML = item
      var delgrant = `<form method="post" onsubmit="return confirm('Are you sure you want to delete this role?')">
                        <input  name="action" type="hidden" value="del_grant">
                        <input type="hidden" value="${role}" name="role">
                        <input type="hidden" value="${item}" name="name">
                        <input type="submit" value="X" class="button tag error">
                        </form>`;
      row.insertCell(1).innerHTML = delgrant;
      
    });

  })
  .catch(error => {
    console.error("Error: ", error);
  });

  modal.style.display = "block";
  
}


// When the user clicks on <span> (x), close the modal
span.onclick = function() {
  modal.style.display = "none";
}

// When the user clicks anywhere outside of the modal, close it
window.onclick = function(event) {
  if (event.target == modal) {
    modal.style.display = "none";
  }
}

