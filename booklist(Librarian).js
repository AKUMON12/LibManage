// SIDEBAR DROPDOWN - OPTIONAL
const allDropdown = document.querySelectorAll('#sidebar .side-dropdown');
const sidebar = document.getElementById('sidebar');

allDropdown.forEach(item=> {
	const a = item.parentElement.querySelector('a:first-child');
	a.addEventListener('click', function (e) {
		e.preventDefault();

		if(!this.classList.contains('active')) {
			allDropdown.forEach(i=> {
				const aLink = i.parentElement.querySelector('a:first-child');

				aLink.classList.remove('active');
				i.classList.remove('show');
			})
		}

		this.classList.toggle('active');
		item.classList.toggle('show');
	})
})





// SIDEBAR COLLAPSE
const toggleSidebar = document.querySelector('nav .toggle-sidebar');
const allSideDivider = document.querySelectorAll('#sidebar .divider');

// Initially hide the sidebar
sidebar.classList.add('hide'); // Ensure the sidebar starts hidden

// Update dividers for initial hidden state
allSideDivider.forEach(item => {
    item.textContent = '-'; // Set to collapsed state
});

// Add event listener for the burger button
toggleSidebar.addEventListener('click', function () {
    sidebar.classList.toggle('hide'); // Toggle sidebar visibility

    // Update dividers based on the sidebar's visibility state
    if (sidebar.classList.contains('hide')) {
        allSideDivider.forEach(item => {
            item.textContent = '-'; // Collapsed state
        });
        allDropdown.forEach(item => {
            const a = item.parentElement.querySelector('a:first-child');
            a.classList.remove('active'); // Remove active class
            item.classList.remove('show'); // Hide dropdown items
        });
    } else {
        allSideDivider.forEach(item => {
            item.textContent = item.dataset.text; // Restore original text
        });
    }
});

/*
If the whole program above still has an error, please do use the program below

const toggleSidebar = document.querySelector('nav .toggle-sidebar');
const allSideDivider = document.querySelectorAll('#sidebar .divider');

if(sidebar.classList.contains('hide')) {
	allSideDivider.forEach(item=> {
		item.textContent = '-'
	})
	allDropdown.forEach(item=> {
		const a = item.parentElement.querySelector('a:first-child');
		a.classList.remove('active');
		item.classList.remove('show');
	})
} else {
	allSideDivider.forEach(item=> {
		item.textContent = item.dataset.text;
	})
}

toggleSidebar.addEventListener('click', function () {
	sidebar.classList.toggle('hide');

	if(sidebar.classList.contains('hide')) {
		allSideDivider.forEach(item=> {
			item.textContent = '-'
		})

		allDropdown.forEach(item=> {
			const a = item.parentElement.querySelector('a:first-child');
			a.classList.remove('active');
			item.classList.remove('show');
		})
	} else {
		allSideDivider.forEach(item=> {
			item.textContent = item.dataset.text;
		})
	}
})
    */









sidebar.addEventListener('mouseleave', function () {
	if(this.classList.contains('hide')) {
		allDropdown.forEach(item=> {
			const a = item.parentElement.querySelector('a:first-child');
			a.classList.remove('active');
			item.classList.remove('show');
		})
		allSideDivider.forEach(item=> {
			item.textContent = '-'
		})
	}
})



sidebar.addEventListener('mouseenter', function () {
	if(this.classList.contains('hide')) {
		allDropdown.forEach(item=> {
			const a = item.parentElement.querySelector('a:first-child');
			a.classList.remove('active');
			item.classList.remove('show');
		})
		allSideDivider.forEach(item=> {
			item.textContent = item.dataset.text;
		})
	}
})




// PROFILE DROPDOWN
const profile = document.querySelector('nav .profile');
const imgProfile = profile.querySelector('img');
const dropdownProfile = profile.querySelector('.profile-link');

imgProfile.addEventListener('click', function () {
	dropdownProfile.classList.toggle('show');
})




// MENU
const allMenu = document.querySelectorAll('main .content-data .head .menu');

allMenu.forEach(item=> {
	const icon = item.querySelector('.icon');
	const menuLink = item.querySelector('.menu-link');

	icon.addEventListener('click', function () {
		menuLink.classList.toggle('show');
	})
})



window.addEventListener('click', function (e) {
	if(e.target !== imgProfile) {
		if(e.target !== dropdownProfile) {
			if(dropdownProfile.classList.contains('show')) {
				dropdownProfile.classList.remove('show');
			}
		}
	}

	allMenu.forEach(item=> {
		const icon = item.querySelector('.icon');
		const menuLink = item.querySelector('.menu-link');

		if(e.target !== icon) {
			if(e.target !== menuLink) {
				if (menuLink.classList.contains('show')) {
					menuLink.classList.remove('show')
				}
			}
		}
	})
})





// PROGRESSBAR
const allProgress = document.querySelectorAll('main .card .progress');

allProgress.forEach(item=> {
	item.style.setProperty('--value', item.dataset.value)
})






// APEXCHART
var options = {
  series: [{
  name: 'series1',
  data: [31, 40, 28, 51, 42, 109, 100]
}, {
  name: 'series2',
  data: [11, 32, 45, 32, 34, 52, 41]
}],
  chart: {
  height: 350,
  type: 'area'
},
dataLabels: {
  enabled: false
},
stroke: {
  curve: 'smooth'
},
xaxis: {
  type: 'datetime',
  categories: ["2018-09-19T00:00:00.000Z", "2018-09-19T01:30:00.000Z", "2018-09-19T02:30:00.000Z", "2018-09-19T03:30:00.000Z", "2018-09-19T04:30:00.000Z", "2018-09-19T05:30:00.000Z", "2018-09-19T06:30:00.000Z"]
},
tooltip: {
  x: {
    format: 'dd/MM/yy HH:mm'
  },
},
};

//var chart = new ApexCharts(document.querySelector("#chart"), options);
//chart.render();


// program that filters the table to display only the book that matches
document.addEventListener("DOMContentLoaded", () => {
    const searchInput = document.querySelector(".search-books input");
    const searchIcon = document.querySelector(".search-books .icon");
    const bookRows = document.querySelectorAll("tbody tr");

    // Confirm elements are selected
    console.log("Search Input:", searchInput);
    console.log("Search Icon:", searchIcon);
    console.log("Book Rows:", bookRows.length);

    // Function to perform the search
    function searchBooks() {
        const searchQuery = searchInput.value.toLowerCase().trim();
        let bookFound = false;

        console.log("Search Query:", searchQuery);

        // Loop through each book row to check for a match
        bookRows.forEach(row => {
            const bookTitle = row.querySelector("td a").textContent.toLowerCase();

            // Show only the matching row, hide others
            if (bookTitle.includes(searchQuery) && searchQuery) {
                row.style.display = ""; // Show the row if it matches
                bookFound = true;
                console.log("Book Found:", bookTitle);
            } else {
                row.style.display = "none"; // Hide non-matching rows
            }
        });

        // If no book matches, display a message in an alert
        if (!bookFound && searchQuery) {
            alert("No book found with that title.");
        } else if (!searchQuery) {
            // If search input is cleared, show all books
            bookRows.forEach(row => (row.style.display = ""));
            console.log("Cleared search, displaying all books.");
        }
    }

    // Listen for Enter key on the search input
    searchInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            e.preventDefault(); // Prevent form submission if within a form
            searchBooks();
        }
    });

    // Listen for click on the search icon
    searchIcon.addEventListener("click", searchBooks);
});