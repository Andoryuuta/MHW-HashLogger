add_subdirectory(fmt)
add_subdirectory(minhook)

set_target_properties(fmt PROPERTIES FOLDER "extern/fmt")
set_target_properties(minhook PROPERTIES FOLDER "extern/minhook")