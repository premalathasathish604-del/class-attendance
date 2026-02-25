// Basic JS for UI interactions
document.addEventListener('DOMContentLoaded', function() {
    // Current date for attendance inputs
    const dateInputs = document.querySelectorAll('input[type="date"]');
    const today = new Date().toISOString().split('T')[0];
    dateInputs.forEach(input => {
        if (!input.value) input.value = today;
    });

    // Sidebar toggle (mobile)
    // TBD if needed
});
