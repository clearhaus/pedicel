require 'rspec/expectations'

RSpec::Matchers.define :satisfy_schema do |expected|
  match do |actual|
    @check = expected.call(actual)
    @check.success?
  end

  failure_message do |actual|
    <<~EOM
      expected that the given hash satisfy the schema, but:
        #{@check.messages}
    EOM
  end
end

RSpec::Matchers.define :dissatisfy_schema do |expected, mismatches|
  match do |actual|
    check = expected.call(actual)

    @mismatches = mismatches
    @errors = check.errors

    return false if check.success?

    return true unless mismatches

    return false unless check.errors.keys.sort == mismatches.keys.sort

    check.errors.sort.zip(mismatches.sort).each do |error, mismatch|
      # Check key
      return false unless error.first == mismatch.first

      # Check messages
      next unless mismatch.last.is_a?(Array)
      return false if error.last.length > mismatch.last.length

      error.last.zip(mismatch.last).each do |error_message, mismatch_message|
        case mismatch_message
        when String
          return false unless error_message == mismatch_message
        when Regexp
          return false unless error_message =~ mismatch_message
        else
          fail "unknown match type for '#{mismatch_message}'"
        end
      end
    end

    true
  end

  failure_message do |actual|
    <<~EOM
      expected that the given hash unsatisfy the schema this way:
        #{@mismatches}
      but got:
        #{@errors}
    EOM
  end
end
