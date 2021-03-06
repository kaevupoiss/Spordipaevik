let sport_select = document.getElementById('sport2');
let type_select = document.getElementById('type');

sport_select.onchange = function() {
  sport = sport_select.value;

  fetch('/new_log/' + sport).then(function(response) {

    response.json().then(function(data) {
        let optionHTML = '';

        for (let type of data.types) {
          optionHTML += '<option value="' + type.id + '">' + type.type + '</option>';
        };

        type_select.innerHTML = optionHTML;
    });
  });
}
