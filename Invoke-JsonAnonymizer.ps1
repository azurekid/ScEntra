param(
    [Parameter(Mandatory = $false)]
    [string]$InputPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter()]
    [string]$Salt = "replace-with-a-private-salt"
)

function Invoke-JsonAnonymizer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter()]
        [string]$Salt = "replace-with-a-private-salt"
    )

    # Small dictionaries (A–Z coverage)
    $FirstNames = @(
        "Aaron", "Abigail", "Adam", "Adrian", "Aisha", "Albert", "Alejandro", "Alex", "Alice", "Alicia",
        "Barbara", "Benjamin", "Beth", "Blake", "Brandon", "Brenda", "Brian", "Brittany", "Bruce", "Bella",
        "Caleb", "Cameron", "Carla", "Carlos", "Carmen", "Caroline", "Catherine", "Chad", "Charlotte", "Chloe",
        "Daniel", "Danielle", "David", "Daphne", "Deborah", "Dennis", "Derek", "Diana", "Diego", "Dominic",
        "Edward", "Elaine", "Eleanor", "Elena", "Eli", "Elijah", "Elizabeth", "Ella", "Ellen", "Emily",
        "Faith", "Felix", "Fernando", "Fiona", "Florence", "Francis", "Frank", "Frederick", "Frida", "Floyd",
        "Gabriel", "Gail", "Gary", "George", "Georgia", "Gerald", "Gloria", "Grace", "Gregory", "Gwen",
        "Hannah", "Harold", "Harry", "Heather", "Helen", "Henry", "Hugo", "Hunter", "Hazel", "Hope",
        "Isabel", "Isaac", "Isabella", "Ivan", "Ivy", "Ignacio", "Imogen", "Ingrid", "Irina", "Iris",
        "Jack", "Jacob", "James", "Jamie", "Janet", "Jared", "Jason", "Jasmine", "Jean", "Jeffrey",
        "Karen", "Katherine", "Kathleen", "Kayla", "Keith", "Kelly", "Kenneth", "Kevin", "Kimberly", "Kara",
        "Laura", "Lauren", "Lawrence", "Leah", "Leo", "Leonard", "Liam", "Linda", "Lisa", "Logan",
        "Madeline", "Madison", "Manuel", "Marcus", "Margaret", "Maria", "Mariah", "Marie", "Marilyn", "Mario",
        "Nathan", "Natalie", "Nathaniel", "Nicholas", "Nicole", "Noah", "Norman", "Nina", "Nora", "Nolan",
        "Olivia", "Oscar", "Omar", "Ophelia", "Orlando", "Owen", "Octavia", "Odette", "Orla", "Otis",
        "Pamela", "Patricia", "Patrick", "Paul", "Paula", "Peter", "Philip", "Phillip", "Phoebe", "Piper",
        "Quentin", "Quincy", "Quinn", "Queen", "Quiana", "Quintin", "Quade", "Quella", "Quirin", "Quadeem",
        "Rachel", "Ralph", "Randy", "Raymond", "Rebecca", "Richard", "Robert", "Roger", "Ronald", "Rose",
        "Samuel", "Sandra", "Sara", "Sarah", "Scott", "Sean", "Sebastian", "Sharon", "Sophia", "Spencer",
        "Taylor", "Teresa", "Thomas", "Tiffany", "Timothy", "Todd", "Tracy", "Tyler", "Tabitha", "Tara",
        "Uma", "Ulysses", "Ulrich", "Uri", "Ursula", "Usman", "Unity", "Urban", "Umair", "Upton",
        "Valerie", "Vanessa", "Victor", "Victoria", "Vincent", "Vera", "Violet", "Vivian", "Valentino", "Valeria",
        "Walter", "Wanda", "Wayne", "Wendy", "William", "Willie", "Wilson", "Winona", "Wyatt", "Whitney",
        "Xander", "Xavier", "Ximena", "Xenia", "Xochitl", "Xyla", "Xavion", "Xia", "Xiomara", "Xerxes",
        "Yara", "Yasmine", "Yolanda", "Yvonne", "Yuri", "Yusuf", "Yael", "Yvette", "Yohan", "Yasmin",
        "Zachary", "Zane", "Zara", "Zelda", "Zoe", "Zora", "Zubair", "Zayd", "Zyra", "Zion"
    )

    $LastNames = @(
        # A
        "Adams", "Ahmed", "Ahn", "Alvarez", "Anderson", "Andrews", "Armstrong", "Atkins", "Austin", "Avila", "Avery", "Abbott",
        # B
        "Bailey", "Baker", "Banks", "Barber", "Barnes", "Barnett", "Barrett", "Barry", "Barton", "Bass", "Beck", "Becker", "Bell", "Bennett", "Benson", "Berry", "Best", "Bird", "Bishop", "Black", "Blair", "Blake", "Boone", "Bowen", "Boyd", "Bradley", "Brady", "Branch", "Brewer", "Bridges", "Bright", "Brock", "Brooks", "Brown", "Bruce", "Bryan", "Bryant", "Buchanan", "Buck", "Burke", "Burns", "Burton", "Bush", "Butler", "Byrd",
        # C
        "Cabrera", "Cain", "Calderon", "Cameron", "Campbell", "Campos", "Carlson", "Carpenter", "Carr", "Carroll", "Carson", "Carter", "Casey", "Castillo", "Castro", "Chambers", "Chan", "Chang", "Chapman", "Charles", "Chavez", "Chen", "Cherry", "Christensen", "Christian", "Clark", "Clarke", "Clay", "Clayton", "Clements", "Cline", "Cobb", "Cochran", "Cole", "Coleman", "Collier", "Collins", "Colon", "Combs", "Conner", "Conrad", "Contreras", "Cook", "Cooper", "Copeland", "Cortez", "Costa", "Cox", "Craig", "Crane", "Crawford", "Cross", "Cruz", "Cummings", "Cunningham", "Curtis",
        # D
        "Dalton", "Daniel", "Daniels", "Davenport", "Davidson", "Davis", "Dawson", "Day", "Dean", "Decker", "Delacruz", "Delaney", "Deleon", "Delgado", "Dennis", "Diaz", "Dickerson", "Dickson", "Dillard", "Dixon", "Dominguez", "Donaldson", "Donovan", "Dorsey", "Douglas", "Downs", "Doyle", "Drake", "Dudley", "Duffy", "Duncan", "Dunn", "Duran", "Durham", "Dyer",
        # E
        "Eaton", "Edwards", "Elliott", "Ellis", "Emerson", "England", "English", "Erickson", "Espinoza", "Estes", "Estrada", "Evans", "Everett", "Ewing",
        # F
        "Farmer", "Farrell", "Faulkner", "Ferguson", "Fernandez", "Fields", "Figueroa", "Finch", "Finley", "Fischer", "Fisher", "Fitzgerald", "Fleming", "Fletcher", "Flores", "Flowers", "Floyd", "Flynn", "Foley", "Ford", "Foreman", "Foster", "Fowler", "Fox", "Francis", "Franco", "Frank", "Franklin", "Freeman", "French", "Frost", "Fry", "Fuentes", "Fuller",
        # G
        "Gaines", "Gallagher", "Gallegos", "Galloway", "Gamble", "Garcia", "Gardner", "Garner", "Garrison", "Garza", "Gates", "Gay", "George", "Gibbs", "Gibson", "Gilbert", "Giles", "Gill", "Gillespie", "Gilliam", "Gilmore", "Glass", "Glenn", "Glover", "Golden", "Gomez", "Gonzalez", "Goodman", "Goodwin", "Gordon", "Gould", "Graham", "Grant", "Graves", "Gray", "Green", "Greene", "Greer", "Gregory", "Griffin", "Grimes", "Gross", "Guerra", "Guerrero", "Gutierrez", "Guzman",
        # H
        "Hahn", "Hale", "Haley", "Hall", "Hamilton", "Hammond", "Hampton", "Hancock", "Hansen", "Hanson", "Hardin", "Harding", "Hardy", "Harmon", "Harper", "Harris", "Harrison", "Hart", "Hartman", "Harvey", "Hawkins", "Hayden", "Hayes", "Haynes", "Hays", "Heath", "Hebert", "Henderson", "Hendricks", "Hendrix", "Henry", "Hensley", "Henson", "Hernandez", "Herrera", "Herring", "Hess", "Hester", "Hewitt", "Hickman", "Hicks", "Higgins", "Hill", "Hines", "Hinton", "Hobbs", "Hodge", "Hodges", "Hoffman", "Hogan", "Holcomb", "Holden", "Holland", "Holloway", "Holmes", "Holt", "Hood", "Hooper", "Hoover", "Hopkins", "Horn", "Horton", "House", "Houston", "Howard", "Howe", "Howell", "Hubbard", "Hudson", "Huff", "Huffman", "Hughes", "Hull", "Humphrey", "Hunt", "Hunter", "Hurley", "Hurst", "Hutchinson", "Hyde",
        # I
        "Ibarra", "Ingram", "Irwin", "Ishikawa", "Iverson",
        # J
        "Jackson", "Jacobs", "James", "Jarvis", "Jefferson", "Jenkins", "Jennings", "Jensen", "Jimenez", "Johnson", "Johnston", "Jones", "Jordan", "Joseph", "Joyce", "Juarez", "Justice",
        # K
        "Kane", "Kaufman", "Keith", "Keller", "Kelley", "Kelly", "Kemp", "Kennedy", "Kent", "Kerr", "Key", "Khan", "Kim", "King", "Kinney", "Kirby", "Kirk", "Kirkland", "Klein", "Knight", "Knox", "Koch", "Kramer", "Krueger", "Kuhn", "Kumar",
        # L
        "Lamb", "Lambert", "Lancaster", "Landry", "Lane", "Lang", "Langley", "Lara", "Larsen", "Larson", "Lawrence", "Lawson", "Le", "Leach", "Leblanc", "Lee", "Leon", "Leonard", "Lester", "Levine", "Lewis", "Li", "Lin", "Little", "Livingston", "Lloyd", "Logan", "Long", "Lopez", "Love", "Lowe", "Lowery", "Lucas", "Luna", "Lynch", "Lyons",
        # M
        "Macdonald", "Macias", "Mack", "Madden", "Maddox", "Maldonado", "Malone", "Mann", "Manning", "Marks", "Marquez", "Marsh", "Marshall", "Martin", "Martinez", "Mason", "Massey", "Mathews", "Mathis", "Matthews", "Maxwell", "May", "Mayer", "Maynard", "Mayo", "Mays", "McBride", "McCall", "McCarthy", "McCormick", "McCoy", "McDaniel", "McDonald", "McDowell", "McFadden", "McFarland", "McGee", "McGuire", "McIntosh", "McKay", "McKee", "McKenzie", "McKinney", "McKnight", "McLaughlin", "McLean", "McMahon", "McMillan", "McNeil", "McPherson", "Meadows", "Medina", "Mejia", "Melendez", "Melton", "Mendez", "Mendoza", "Mercado", "Mercer", "Merrill", "Merritt", "Meyer", "Meyers", "Michael", "Middleton", "Miles", "Miller", "Mills", "Miranda", "Mitchell", "Molina", "Monroe", "Montgomery", "Montoya", "Moody", "Moon", "Moore", "Morales", "Moran", "Moreno", "Morgan", "Morris", "Morrison", "Morrow", "Morse", "Morton", "Moses", "Mosley", "Moss", "Mueller", "Mullen", "Mullins", "Munoz", "Murphy", "Murray", "Myers",
        # N
        "Nash", "Navarro", "Neal", "Nelson", "Newman", "Nguyen", "Nichols", "Nicholson", "Nielsen", "Nixon", "Noble", "Noel", "Nolan", "Norman", "Norris", "Norton", "Nunez",
        # O
        "Obrien", "Ochoa", "Oconnor", "Odom", "O'Donnell", "O'Neill", "Oliver", "Olsen", "Olson", "Oneal", "Oneill", "Orr", "Ortega", "Ortiz", "Osborn", "Osborne", "Osgood", "Owen", "Owens",
        # P
        "Pace", "Padilla", "Page", "Palmer", "Park", "Parker", "Parks", "Parrish", "Parsons", "Patel", "Patrick", "Patterson", "Patton", "Paul", "Payne", "Pearson", "Peck", "Pena", "Pennington", "Perez", "Perkins", "Perry", "Peters", "Peterson", "Pham", "Phillips", "Pierce", "Pittman", "Plummer", "Poole", "Pope", "Porter", "Potter", "Powell", "Powers", "Pratt", "Preston", "Price", "Prince", "Pruitt",
        # Q
        "Qualls", "Quarles", "Queen", "Quigley", "Quinn", "Quintana", "Quintero", "Quirino",
        # R
        "Ramirez", "Ramos", "Randall", "Randolph", "Rasmussen", "Ray", "Raymond", "Reed", "Reese", "Reid", "Reilly", "Reyes", "Reynolds", "Rhodes", "Rice", "Rich", "Richard", "Richards", "Richardson", "Riley", "Rios", "Rivas", "Rivera", "Robbins", "Roberson", "Roberts", "Robertson", "Robinson", "Robles", "Rocha", "Rodgers", "Rodriguez", "Rogers", "Roman", "Romero", "Rosales", "Rosario", "Rose", "Ross", "Rowe", "Roy", "Ruiz", "Russell", "Rutledge", "Ryan",
        # S
        "Sanchez", "Sanders", "Santana", "Santiago", "Saunders", "Savage", "Schmidt", "Schneider", "Scott", "Sears", "Segura", "Sellers", "Serrano", "Shaw", "Shelton", "Shepard", "Shepherd", "Sherman", "Silva", "Simmons", "Simon", "Simpson", "Sims", "Singh", "Skinner", "Smith", "Snow", "Snyder", "Solomon", "Soto", "Sparks", "Spencer", "Stanley", "Steele", "Stein", "Stephens", "Stephenson", "Stevens", "Stewart", "Stokes", "Stone", "Strickland", "Strong", "Suarez", "Sullivan", "Summers", "Sutton", "Swanson", "Sweet", "Swift",
        # T
        "Taylor", "Terrell", "Thomas", "Thompson", "Thornton", "Tillman", "Todd", "Torres", "Townsend", "Tracy", "Tran", "Travis", "Trevino", "Trujillo", "Tucker", "Turner", "Tyler",
        # U
        "Underwood", "Upton", "Urban", "Uribe", "Ursu", "Usman", "Utley",
        # V
        "Valdez", "Valencia", "Valentine", "Valenzuela", "Vance", "Vang", "Vargas", "Vasquez", "Vaughn", "Vazquez", "Vega", "Velasquez", "Velazquez", "Velez", "Veloso", "Venable", "Vera", "Vergara", "Verma", "Vick", "Vickers", "Vigil", "Villarreal", "Vincent", "Vinson", "Viteri", "Vogel", "Voss",
        # W
        "Wade", "Wagner", "Walker", "Wall", "Wallace", "Waller", "Walls", "Walsh", "Walter", "Walters", "Walton", "Wang", "Ward", "Ware", "Warner", "Warren", "Washington", "Waters", "Watkins", "Watson", "Watt", "Watts", "Weaver", "Webb", "Weber", "Webster", "Weeks", "Weiss", "Welch", "Wells", "West", "Wheeler", "Whitaker", "White", "Whitehead", "Whitfield", "Whitley", "Whitney", "Wiggins", "Wilcox", "Wilder", "Wiles", "Wilkerson", "Wilkins", "Wilkinson", "William", "Williams", "Williamson", "Willis", "Wilson", "Winters", "Wise", "Witt", "Wolf", "Wolfe", "Wong", "Wood", "Woodard", "Woods", "Woodward", "Wooten", "Wright", "Wu", "Wyatt",
        # X
        "Xander", "Xiao", "Xiong", "Xu", "Xue",
        # Y
        "Yamada", "Yan", "Yang", "Yates", "Yazdi", "Ye", "Yoder", "York", "Young", "Yu",
        # Z
        "Zamora", "Zapata", "Zarate", "Zavala", "Zayas", "Zhang", "Zhao", "Ziegler", "Zimmer", "Zimmerman", "Zuniga"
    )

    function Get-HashHex([string]$s, [string]$salt) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($salt + $s)
            $hash = $sha.ComputeHash($bytes)
            return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
        }
        finally { $sha.Dispose() }
    }

    function Generate-Name([string]$value) {
        $h = Get-HashHex $value $Salt
        $firstIndex = [Convert]::ToInt32($h.Substring(0, 4), 16) % $FirstNames.Count
        $lastIndex = [Convert]::ToInt32($h.Substring(4, 4), 16) % $LastNames.Count
        return "$($FirstNames[$firstIndex]) $($LastNames[$lastIndex])"
    }

    function Generate-UPN([string]$value) {
        $h = Get-HashHex $value $Salt
        $firstIndex = [Convert]::ToInt32($h.Substring(0, 4), 16) % $FirstNames.Count
        $lastIndex = [Convert]::ToInt32($h.Substring(4, 4), 16) % $LastNames.Count
        $localPart = ($FirstNames[$firstIndex] + "." + $LastNames[$lastIndex]).ToLower()
        return "$localPart@azurehacking.com"
    }

    function Alias-Group([string]$name) {
        $h = Get-HashHex $name $Salt
        return "Group-" + $h.Substring(0, 6)
    }

    function Alias-App([string]$name) {
        $h = Get-HashHex $name $Salt
        return "App-" + $h.Substring(0, 6)
    }

    function Anonymize-Value([string]$key, $value, $context = $null) {
        if ($null -eq $value) { return $null }
        if ($value -isnot [string]) { return $value }

        $lk = ($key ?? '').ToLower()

        # Special handling for graph nodes
        if ($context -and $context.type -eq 'user') {
            if ($lk -eq 'label') { return Generate-Name $value }
            if ($lk -eq 'userprincipalname') { return Generate-UPN $value }
        }

        if ($lk -eq 'principaldisplayname') { return Generate-Name $value }
        if ($lk -eq 'userprincipalname') { return Generate-UPN $value }
        if ($lk -match 'app|serviceprincipal') { return Alias-App $value }
        if ($lk -match 'group|members|owners') { return Alias-Group $value }
        if ($lk -match 'displayname|owner|manager|givenname|surname') { return Generate-Name $value }

        return $value
    }

    function Anonymize-Obj($obj, $context = $null) {
        if ($null -eq $obj) { return $null }

        if ($obj -is [System.Collections.IDictionary] -or $obj -is [PSCustomObject]) {
            $new = @{}
            
            # Build context if this is a node with a type
            $currentContext = $context
            if ($obj.PSObject.Properties.Name -contains 'type') {
                $currentContext = @{ type = $obj.type }
            }
            
            # For user nodes, we need to generate consistent names based on ORIGINAL values
            $generatedName = $null
            if ($currentContext -and $currentContext.type -eq 'user') {
                # Use the ORIGINAL label or id as the seed for consistent anonymization
                $seed = $null
                if ($obj.PSObject.Properties.Name -contains 'label' -and $obj.label) {
                    $seed = $obj.label  # Use original label before anonymization
                } elseif ($obj.PSObject.Properties.Name -contains 'id' -and $obj.id) {
                    $seed = $obj.id
                }
                if ($seed) {
                    $generatedName = Generate-Name $seed
                }
            }
            
            foreach ($k in $obj.PSObject.Properties.Name) {
                $v = $obj.$k
                $lk = $k.ToLower()
                
                # For user nodes, use consistent name across label and UPN
                if ($currentContext -and $currentContext.type -eq 'user' -and $generatedName) {
                    if ($lk -eq 'label') {
                        $new[$k] = $generatedName
                        continue
                    }
                    if ($lk -eq 'userprincipalname') {
                        # Convert "First Last" to "first.last@azurehacking.com"
                        $nameParts = $generatedName -split '\s+', 2
                        if ($nameParts.Count -eq 2) {
                            $upn = ($nameParts[0] + "." + $nameParts[1]).ToLower() + "@azurehacking.com"
                        } else {
                            $upn = $generatedName.ToLower().Replace(' ', '.') + "@azurehacking.com"
                        }
                        $new[$k] = $upn
                        continue
                    }
                }
                
                # For scalar values, apply Anonymize-Value then recurse
                # For complex objects, just recurse with Anonymize-Obj
                if ($v -is [string]) {
                    $new[$k] = Anonymize-Value $k $v $currentContext
                } else {
                    $new[$k] = Anonymize-Obj $v $currentContext
                }
            }
            return $new
        }

        if ($obj -is [System.Collections.IEnumerable] -and $obj.GetType().Name -ne 'String') {
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($item in $obj) {
                $anonItem = Anonymize-Obj $item $context
                $list.Add($anonItem)
            }
            return $list.ToArray()
        }

        return $obj
    }

    $raw = Get-Content -Path $InputPath -Raw -ErrorAction Stop
    $data = $raw | ConvertFrom-Json -Depth 100
    $anon = Anonymize-Obj $data
    $json = ($anon | ConvertTo-Json -Depth 100)
    Set-Content -Path $OutputPath -Value $json -Encoding UTF8
    return $anon
}

# If script is run with parameters, execute the function
if ($InputPath -and $OutputPath) {
    Invoke-JsonAnonymizer -InputPath $InputPath -OutputPath $OutputPath -Salt $Salt
}
