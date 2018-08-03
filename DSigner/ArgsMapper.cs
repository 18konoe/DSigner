/*
  LICENSE
  -------
  Copyright (C) 2018 Juhachi Konoe

  This source code is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this source code or the software it produces.

  Permission is granted to anyone to use this source code for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this source code must not be misrepresented; you must not
     claim that you wrote the original source code.  If you use this source code
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original source code.
  3. This notice may not be removed or altered from any source distribution.
*/

using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace DSigner
{
    public class ArgsMapper
    {
        public IReadOnlyList<string> ArgsList => new ReadOnlyCollection<string>(_argsList);

        public IReadOnlyList<string> SwitchList => new ReadOnlyCollection<string>(_switchList);
        public IReadOnlyDictionary<string, string> OptionDictionary => new ReadOnlyDictionary<string, string>(_optionDictionary);
        private readonly List<string> _argsList = new List<string>();
        private readonly List<string> _switchList = new List<string>();
        private readonly Dictionary<string, string> _optionDictionary = new Dictionary<string, string>();

        public string GetOption(string key, string defaultValue = null)
        {
            if (_optionDictionary.ContainsKey(key))
            {
                return _optionDictionary[key];
            }

            return defaultValue;
        }

        public ArgsMapper(string[] args)
        {
            int i = 0;
            while (i < args.Length)
            {
                string arg = args[i];
                if (arg.StartsWith("-"))
                {
                    if (i + 1 < args.Length)
                    {
                        if (args[i + 1].StartsWith("-"))
                        {
                            _switchList.Add(args[i]);
                        }
                        else
                        {
                            _optionDictionary[arg] = args[i + 1];
                            i++;
                        }
                    }
                    else
                    {
                        _switchList.Add(args[i]);
                    }
                }
                else
                {
                    _argsList.Add(arg);
                }

                i++;
            }
        }
    }
}