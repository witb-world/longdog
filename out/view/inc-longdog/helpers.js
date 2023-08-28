// Rough sketch of templating helper functions, supposing we use Handlebars.js (based on ScoutSuite)

// sorting helper function
Handlebars.registerHelper('each_dict_as_sorted_list', function (context, options) {
    var ret = ''

    var sortedFindingsKeys = Object.keys(context).sort(function (a, b) {
        if (context[a].flagged_items === 0 && context[b].flagged_items === 0) {
            if (context[a].checked_items === 0 && context[b].checked_items !== 0) return 1
            if (context[a].checked_items !== 0 && context[b].checked_items === 0) return -1
            if (context[a].description.toLowerCase() < context[b].description.toLowerCase()) return -1
            if (context[a].description.toLowerCase() > context[b].description.toLowerCase()) return 1
        }
        if ((context[a].flagged_items == 0 && context[b].flagged_items > 0) ||
            (context[a].flagged_items > 0 && context[b].flagged_items === 0)) {
            if (context[a].flagged_items > context[b].flagged_items) return -1
            return 1
        }
        if (context[a].flagged_items > 0 && context[b].flagged_items > 0) {
            if (context[a].level === context[b].level) {
                if (context[a].description.toLowerCase() < context[b].description.toLowerCase()) return -1
                if (context[a].description.toLowerCase() > context[b].description.toLowerCase()) return 1
            } else {
                if (context[a].level.toLowerCase() === 'danger') return -1
                if (context[b].level.toLowerCase() === 'danger') return 1
                if (context[a].level.toLowerCase() === 'warning') return -1 // FIXME - these are duplicated for nothing?
                if (context[b].level.toLowerCase() === 'warning') return 1
                if (context[a].level.toLowerCase() === 'warning') return -1
                if (context[b].level.toLowerCase() === 'warning') return 1
            }
        }
        return 0
    })

    sortedFindingsKeys.forEach(function (key) {
        var obj = context[key]
        obj['key'] = key
        // sorted_findings.push(obj)
        ret += options.fn(obj)
    })

    return ret
})

Handlebars.registerHelper('dashboard_color', function (level, checked, flagged) {
    if (checked === 0) {
        return 'unknown disabled-link'
    } else if (flagged === 0) {
        return 'good disabled-link'
    } else {
        return level
    }
})