module PacketGen
  module Header
    class DNS

      # Mixin module for {RR} and {Question}.
      # @author Sylvain Daubert
      module BaseRR

        # Getter for type
        # @return [Integer]
        def type
          self[:type].to_i
        end

        # Setter for type
        # @param [Integer] val
        # @return [Integer,String]
        def type=(val)
          v = case val
              when String
                self.class::TYPES[val.upcase]
              else
                val
              end
          raise ArgumentError, "unknown type #{val.inspect}" unless v
          self[:type].read v
        end

        # Check type
        # @param [String] type name
        # @return [Boolean]
        def has_type?(type)
          self.class::TYPES[type] == self.type
        end

        # Getter for class
        # @return [Integer]
        def rrclass
          self[:rrclass].to_i
        end

        # Setter for class
        # @param [Integer] val
        # @return [Integer,String]
        def rrclass=(val)
              v = case val
                  when String
                    self.class::CLASSES[val.upcase]
                  else
                    val
                  end
          raise ArgumentError, "unknown class #{val.inspect}" unless v
          self[:rrclass].read v
        end
          
        # Get human readable type
        # @return [String]
          def human_type
          self.class::TYPES.key(type) || "0x%04x" % type
        end

        # Get human readable class
        # @return [String]
        def human_rrclass
          self.class::CLASSES.key(self.rrclass) || "0x%04x" % self.rrclass
        end

      end
    end
  end
end
