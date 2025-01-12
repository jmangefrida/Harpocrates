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

var managegrant = `
<h3>Add Grant</h3>
<p>
<form method=post>
  <input name='action' type='hidden' value='manage_grant'>
  <input name='name' type='text' placeholder='Name'>
  <p><p>
  <input name='description' type='text' placeholder='Description'>
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

