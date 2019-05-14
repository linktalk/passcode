// Status
var pwdStatus = {
  inputMask: 0x00,
  yourPasscode: "",
  yourSlogan: "",
  accountDomain: "",
  accountUsername: "",
  encoder: new TextEncoder(),
  byteMap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
           'abcdefghijklmnopqrstuvwxyz' +
           '0123456789' +
           '!@#$%^&*()_-+={[}]|:;<,>.?/' +
           'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
           'abcdefghijklmnopqrstuvwxyz' +
           '0123456789' +
           '!@#$%^&*()_-+={[}]|:;<,>.?/' +
           'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
           'abcdefghijklmnopqrstuvwxyz' +
           '0123456789' +
           '!@#$%^&*()_-+={[}]|:;<,>.?/'
};

window.onload = function() {
    document.getElementById("yourPasscode")
            .querySelector("input").onchange = function() {
      if (!this.checkValidity()) {
        showAlert("Your One Password is invalid: Need 6+ characters");
        return false;
      }

      pwdStatus.yourPasscode = this.value;
      show(this, "yourSlogan", 0x01, true);
    };

    document.getElementById("yourPasscode")
            .querySelector("input").onblur = function() {
      if (pwdStatus.yourSlogan != this.value) {
        if (!this.checkValidity()) {
          showAlert("Your One Password is invalid: use 6 or more characters");
          return false;
        }

        pwdStatus.yourPasscode = this.value;
        show(this, "yourSlogan", 0x01, true);
      }
    };

    document.getElementById("yourSlogan")
            .querySelector("input").onchange = function() {
      pwdStatus.yourSlogan = this.value;
      show(this, "accountDomain", 0x02, true);
    };

    document.getElementById("accountDomain")
            .querySelector("input").onchange = function() {
      pwdStatus.accountDomain = this.value;
      show(this, "accountUsername", 0x04, true);
    };

    document.getElementById("accountUsername")
            .querySelector("input").onchange = function() {
      pwdStatus.accountUsername = this.value;
      show(this, "accountPassword", 0x08, false);
    };
};

function show(current, id, mask, hasNextInput) {
  var n = document.getElementById(id);
  if ((pwdStatus.inputMask & mask) == 0x00) {
    n.style.visibility = "visible";
    pwdStatus.inputMask |= mask;
  }

  if (hasNextInput) {
    n.querySelector("input").focus();
  } else {
    current.blur();
  }

  if ((pwdStatus.inputMask & 0x0F) == 0x0F) {
      generatePassword();
  }

  return true;
}

function generatePassword() {
  var o = document.getElementById("accountPassword").querySelector("output");
  window.crypto.subtle.importKey(
    "raw",
    pwdStatus.encoder.encode(
        pwdStatus.yourPasscode.trim() +
        pwdStatus.yourSlogan.trim()),
    {
      name: "PBKDF2"
    },
    false,
    ["deriveBits"]
  ).then(function(kdfKey) {
    derivePassword(kdfKey, o);
  }).catch(function(err) {
    o.value = "Unable to generate account password: " + err;
  });
}

function derivePassword(kdfKey, o) {
  window.crypto.subtle.deriveBits(
    {
      "name": "PBKDF2",
      salt: pwdStatus.encoder.encode(
          pwdStatus.accountDomain.trim().toUpperCase() +
          pwdStatus.accountUsername.trim()),
      "iterations": 100000,
      "hash": "SHA-256"
    },
    kdfKey,
    160
  ).then(function(keyArray) {
    var keyBytes = new Uint8Array(keyArray);
    var devivedPassword = "";
    for (var i = 0; i < keyBytes.byteLength; i++) {
        devivedPassword += pwdStatus.byteMap[keyBytes[i]];
    }

    o.value = devivedPassword;
  }).catch(function(err) {
    o.value = "Unable to generate account password: " + err;
  });
}

function showAlert(m) {
  document.getElementById("accountPassword").querySelector("output").value = m;
}

